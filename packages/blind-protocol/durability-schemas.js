import b4a from 'b4a'
import {
  arrayOf,
  boundedBytes,
  canonicalAsciiBytes,
  constant,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from './codec.js'
import { protocolError } from './errors.js'

const KiB = 1024
const MiB = 1024 * KiB
const bytes24 = fixedBytes(24)
const bytes32 = fixedBytes(32)
const bytes64 = fixedBytes(64)
const version1 = constant(u8, 1, 'version')

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function nonzero (value, field) {
  if (isZero(value)) fail(`${field} must be nonzero`)
}

function asU64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${field} is outside u64`)
  return value
}

function compareBytes (left, right) {
  return b4a.compare(left, right)
}

function capped (encoding, maximum, name) {
  return {
    preencode (state, value) {
      const start = state.end
      encoding.preencode(state, value)
      if (state.end - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
    },
    encode (state, value) { encoding.encode(state, value) },
    decode (state) {
      const start = state.start
      const value = encoding.decode(state)
      if (state.start - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
      return value
    }
  }
}

export const durabilityContinuityBindingV1 = struct([
  ['version', version1],
  ['profileId', ranged(u8, 1, 2, 'profileId')],
  ['externalJournalId', bytes32],
  ['externalWitnessPublicKey', bytes32],
  ['externalJournalReplicationClass', ranged(u8, 0, 1, 'externalJournalReplicationClass')],
  ['externalJournalFailureGroupId', bytes32],
  ['restoreEvidenceFeedId', bytes32]
], {
  name: 'DurabilityContinuityBindingV1',
  validate (value) {
    const external = [
      value.externalJournalId,
      value.externalWitnessPublicKey,
      value.externalJournalFailureGroupId
    ]
    if (value.profileId === 1) {
      if (value.externalJournalReplicationClass !== 0 || external.some(value => !isZero(value)) ||
          !isZero(value.restoreEvidenceFeedId)) fail('profile 1 continuity binding must contain only zero external state')
    } else if (value.externalJournalReplicationClass !== 1 || external.some(isZero)) {
      fail('profile 2 continuity binding requires the external journal identity, witness, class, and failure group')
    }
  }
})

export const blindBackupEncryptionProfileV1 = struct([
  ['version', version1],
  ['algorithmId', constant(u16be, 1, 'algorithmId')],
  ['keyDerivationId', constant(u16be, 1, 'keyDerivationId')],
  ['recoveryKeyId', bytes32],
  ['keyEpoch', ranged(u32be, 1, 0xffffffff, 'keyEpoch')]
], {
  name: 'BlindBackupEncryptionProfileV1',
  validate (value) { nonzero(value.recoveryKeyId, 'recoveryKeyId') }
})

const backupChunkEntryV1 = struct([
  ['path', canonicalAsciiBytes(1, 512, 'path')],
  ['fileOffset', u64be],
  ['plaintextByteLength', ranged(u32be, 1, 4 * MiB, 'plaintextByteLength')],
  ['ciphertextByteLength', ranged(u32be, 17, 4 * MiB + 16, 'ciphertextByteLength')],
  ['chunkObjectId', bytes32],
  ['chunkSalt', bytes32],
  ['nonce', bytes24],
  ['ciphertextHash', bytes32]
], {
  name: 'BlindBackupChunkManifestEntryV1',
  validate (value) {
    nonzero(value.chunkObjectId, 'chunkObjectId')
    nonzero(value.chunkSalt, 'chunkSalt')
    nonzero(value.ciphertextHash, 'ciphertextHash')
    const path = b4a.toString(value.path, 'ascii')
    if (path.startsWith('/') || path.endsWith('/') || path.includes('\\') ||
        path.split('/').some(part => part === '' || part === '.' || part === '..')) {
      fail('backup path must be a portable relative ASCII path')
    }
  }
})

export const blindBackupChunkManifestV1 = struct([
  ['version', version1],
  ['backupId', bytes32],
  ['encryptionProfile', blindBackupEncryptionProfileV1],
  ['encryptionManifestHash', bytes32],
  ['entries', arrayOf(backupChunkEntryV1, 1, 0x1000000, 'entries')],
  ['totalPlaintextByteLength', u64be],
  ['totalCiphertextByteLength', u64be]
], {
  name: 'BlindBackupChunkManifestV1',
  validate (value) {
    nonzero(value.backupId, 'backupId')
    nonzero(value.encryptionManifestHash, 'encryptionManifestHash')
    let plaintext = 0n
    let ciphertext = 0n
    for (let index = 0; index < value.entries.length; index++) {
      const entry = value.entries[index]
      plaintext += BigInt(entry.plaintextByteLength)
      ciphertext += BigInt(entry.ciphertextByteLength)
      if (index > 0) {
        const previous = value.entries[index - 1]
        const order = compareBytes(previous.path, entry.path)
        if (order > 0 || (order === 0 && asU64(previous.fileOffset, 'fileOffset') >= asU64(entry.fileOffset, 'fileOffset'))) {
          fail('backup chunk entries must be strictly sorted by path and file offset')
        }
      }
    }
    if (plaintext !== asU64(value.totalPlaintextByteLength, 'totalPlaintextByteLength') ||
        ciphertext !== asU64(value.totalCiphertextByteLength, 'totalCiphertextByteLength')) {
      fail('backup chunk totals do not equal the entry totals')
    }
  }
})

export const blindBackupManifestV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['backupId', bytes32],
  ['backupFailureGroupId', bytes32],
  ['storeManifestRevision', u64be],
  ['storeManifestHash', bytes32],
  ['storeFormatHash', bytes32],
  ['coverageCutoffExternalUnixMillis', u64be],
  ['coveredWalSequence', u64be],
  ['coveredWalHash', bytes32],
  ['externalFloorRevision', u64be],
  ['externalFloorHash', bytes32],
  ['externalCheckpointRevision', u64be],
  ['externalCheckpointHash', bytes32],
  ['baseFloorRevision', u64be],
  ['baseFloorHash', bytes32],
  ['controlSnapshotHash', bytes32],
  ['backupEncryptionProfileHash', bytes32],
  ['encryptionManifestHash', bytes32],
  ['chunkManifestByteLength', u64be],
  ['chunkManifestHash', bytes32],
  ['totalPlaintextByteLength', u64be],
  ['totalCiphertextByteLength', u64be],
  ['restoreVerifierPublicKey', optional(bytes32, 'restoreVerifierPublicKey')],
  ['cleanRestoreEvidenceHash', optional(bytes32, 'cleanRestoreEvidenceHash')],
  ['createdExternalUnixMillis', u64be],
  ['restoreSupportExpiresUnixMillis', u64be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindBackupManifestV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash', 'backupId',
      'backupFailureGroupId', 'storeManifestHash', 'storeFormatHash', 'coveredWalHash',
      'externalFloorHash', 'externalCheckpointHash', 'baseFloorHash', 'controlSnapshotHash',
      'backupEncryptionProfileHash', 'encryptionManifestHash', 'chunkManifestHash', 'witnessPublicKey'
    ]) nonzero(value[field], field)
    if ((value.restoreVerifierPublicKey == null) !== (value.cleanRestoreEvidenceHash == null)) {
      fail('restore verifier and clean restore evidence hash must be present together')
    }
    if (value.restoreVerifierPublicKey != null) {
      nonzero(value.restoreVerifierPublicKey, 'restoreVerifierPublicKey')
      nonzero(value.cleanRestoreEvidenceHash, 'cleanRestoreEvidenceHash')
    }
    if (asU64(value.createdExternalUnixMillis, 'createdExternalUnixMillis') >=
        asU64(value.restoreSupportExpiresUnixMillis, 'restoreSupportExpiresUnixMillis')) {
      fail('restore support expiry must be after backup creation')
    }
  }
})

export const blindCleanRestoreEvidenceV1 = struct([
  ['version', version1],
  ['backupId', bytes32],
  ['backupCandidateCommitment', bytes32],
  ['restoredStoreManifestHash', bytes32],
  ['verifiedWalSequence', u64be],
  ['verifiedWalHash', bytes32],
  ['verifiedExternalFloorRevision', u64be],
  ['verifiedExternalFloorHash', bytes32],
  ['verifiedCheckpointRevision', u64be],
  ['verifiedCheckpointHash', bytes32],
  ['scrubbedObjectCount', u64be],
  ['scrubFailureCount', constant(u32be, 0, 'scrubFailureCount')],
  ['startedExternalUnixMillis', u64be],
  ['completedExternalUnixMillis', u64be],
  ['verifierPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindCleanRestoreEvidenceV1',
  validate (value) {
    for (const field of [
      'backupId', 'backupCandidateCommitment', 'restoredStoreManifestHash', 'verifiedWalHash',
      'verifiedExternalFloorHash', 'verifiedCheckpointHash', 'verifierPublicKey'
    ]) nonzero(value[field], field)
    if (asU64(value.startedExternalUnixMillis, 'startedExternalUnixMillis') >=
        asU64(value.completedExternalUnixMillis, 'completedExternalUnixMillis')) {
      fail('clean restore completion must be after start')
    }
  }
})

export const blindBackupRetentionTransitionV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['backupId', bytes32],
  ['backupManifestHash', bytes32],
  ['transitionRevision', u64be],
  ['previousTransitionHash', optional(bytes32, 'previousTransitionHash')],
  ['operation', ranged(u8, 1, 3, 'operation')],
  ['supportExpiresUnixMillis', u64be],
  ['replacementBackupId', optional(bytes32, 'replacementBackupId')],
  ['effectiveExternalTimeFloorMillis', u64be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindBackupRetentionTransitionV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash', 'backupId',
      'backupManifestHash', 'witnessPublicKey'
    ]) nonzero(value[field], field)
    const revision = asU64(value.transitionRevision, 'transitionRevision')
    if (revision === 0n || (revision === 1n) !== (value.previousTransitionHash == null)) {
      fail('retention transition predecessor presence does not match revision')
    }
    if (value.previousTransitionHash != null) nonzero(value.previousTransitionHash, 'previousTransitionHash')
    if (value.replacementBackupId != null) nonzero(value.replacementBackupId, 'replacementBackupId')
    if ((value.operation === 3) !== (value.replacementBackupId != null)) {
      fail('replacementBackupId is present exactly for RETIRE')
    }
  }
})

export const blindRestoreEvidenceHeadV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['restoreEvidenceFeedId', bytes32],
  ['evidenceSequence', u64be],
  ['previousEvidenceHeadHash', optional(bytes32, 'previousEvidenceHeadHash')],
  ['currentBackupManifestHash', bytes32],
  ['currentRetentionTransitionHash', bytes32],
  ['currentCoveredWalSequence', u64be],
  ['currentExternalFloorRevision', u64be],
  ['currentChunkObjectCount', u64be],
  ['currentAvailabilityAuditHash', bytes32],
  ['currentSupportExpiresUnixMillis', u64be],
  ['drillBackupManifestHash', bytes32],
  ['drillCleanRestoreEvidenceHash', bytes32],
  ['drillRetentionTransitionHash', bytes32],
  ['restoreDrillCompletedUnixMillis', u64be],
  ['drillSupportExpiresUnixMillis', u64be],
  ['issuedExternalUnixMillis', u64be],
  ['expiresExternalUnixMillis', u64be],
  ['issuedEpoch', u32be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindRestoreEvidenceHeadV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash',
      'restoreEvidenceFeedId', 'currentBackupManifestHash', 'currentRetentionTransitionHash',
      'currentAvailabilityAuditHash', 'drillBackupManifestHash', 'drillCleanRestoreEvidenceHash',
      'drillRetentionTransitionHash', 'witnessPublicKey'
    ]) nonzero(value[field], field)
    const sequence = asU64(value.evidenceSequence, 'evidenceSequence')
    if (sequence === 0n || (sequence === 1n) !== (value.previousEvidenceHeadHash == null)) {
      fail('restore evidence predecessor presence does not match sequence')
    }
    const issued = asU64(value.issuedExternalUnixMillis, 'issuedExternalUnixMillis')
    const expires = asU64(value.expiresExternalUnixMillis, 'expiresExternalUnixMillis')
    if (issued >= expires) fail('restore evidence expiry must be after issuance')
    if (BigInt(value.issuedEpoch) !== issued / 21600000n) fail('issuedEpoch does not match external issuance time')
  }
})

const blindRestoreEvidenceBundleBaseV1 = struct([
  ['version', version1],
  ['heads', arrayOf(blindRestoreEvidenceHeadV1, 1, 385, 'heads')],
  ['currentBackupManifestBytes', boundedBytes(1, 0xffff, 'currentBackupManifestBytes')],
  ['currentRetentionTransitionBytes', boundedBytes(1, 8 * KiB, 'currentRetentionTransitionBytes')],
  ['drillBackupManifestBytes', boundedBytes(1, 0xffff, 'drillBackupManifestBytes')],
  ['drillCleanRestoreEvidenceBytes', boundedBytes(1, 8 * KiB, 'drillCleanRestoreEvidenceBytes')],
  ['drillRetentionTransitionBytes', boundedBytes(1, 8 * KiB, 'drillRetentionTransitionBytes')]
], {
  name: 'BlindRestoreEvidenceBundleV1',
  validate (value) {
    for (let index = 1; index < value.heads.length; index++) {
      const previous = value.heads[index - 1]
      const current = value.heads[index]
      if (asU64(current.evidenceSequence, 'evidenceSequence') !==
          asU64(previous.evidenceSequence, 'evidenceSequence') + 1n) {
        fail('restore evidence bundle heads must be contiguous and ordered')
      }
      for (const field of ['relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash', 'restoreEvidenceFeedId']) {
        if (!b4a.equals(previous[field], current[field])) fail(`restore evidence bundle changes ${field}`)
      }
    }
  }
})

export const blindRestoreEvidenceBundleV1 = capped(blindRestoreEvidenceBundleBaseV1,
  512 * KiB, 'BlindRestoreEvidenceBundleV1')
