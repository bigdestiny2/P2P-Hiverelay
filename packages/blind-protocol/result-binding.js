import b4a from 'b4a'
import {
  boundedBytes,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u64be
} from './codec.js'
import { protocolError } from './errors.js'
import { isKnownOperation } from './wire-runtime-authority.js'

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isAllZero (value) {
  for (let index = 0; index < value.byteLength; index++) {
    if (value[index] !== 0) return false
  }
  return true
}

function nonzero (value, name) {
  if (isAllZero(value)) fail(`${name} must be nonzero`)
}

function asBigInt (value, name) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${name} is outside u64`)
  return value
}

const bytes32 = fixedBytes(32)
const bytes64 = fixedBytes(64)

export const blindExternalCommitWitnessV1 = struct([
  ['version', ranged(u8, 1, 1, 'version')],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['restoreEvidenceHeadSequence', u64be],
  ['restoreEvidenceHeadHash', bytes32],
  ['familyId', ranged(u8, 1, 5, 'familyId')],
  ['operationId', ranged(u8, 1, 255, 'operationId')],
  ['requestCommitment', bytes32],
  ['resultCommitment', bytes32],
  ['commitWalSequence', u64be],
  ['commitWalHash', bytes32],
  ['coveringFloorRevision', u64be],
  ['coveringFloorHash', bytes32],
  ['coveringFloorWalSequence', u64be],
  ['coveringFloorWalHash', bytes32],
  ['writerEpoch', u64be],
  ['writerFenceTokenHash', bytes32],
  ['externalLeaseRevision', u64be],
  ['witnessedUnixMillis', u64be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindExternalCommitWitnessV1',
  validate (value) {
    for (const field of [
      'relayPublicKey',
      'storeId',
      'externalJournalId',
      'durabilityContinuityHash',
      'durabilityProfileHash',
      'requestCommitment',
      'resultCommitment',
      'commitWalHash',
      'coveringFloorHash',
      'coveringFloorWalHash',
      'writerFenceTokenHash',
      'witnessPublicKey'
    ]) nonzero(value[field], field)
    if (!isKnownOperation(value.familyId, value.operationId)) fail('external witness references an unknown operation')
    if (asBigInt(value.coveringFloorWalSequence, 'coveringFloorWalSequence') <
        asBigInt(value.commitWalSequence, 'commitWalSequence')) {
      fail('covering floor WAL sequence is below the committed result')
    }
    if (asBigInt(value.coveringFloorRevision, 'coveringFloorRevision') === 0n ||
        asBigInt(value.writerEpoch, 'writerEpoch') === 0n ||
        asBigInt(value.externalLeaseRevision, 'externalLeaseRevision') === 0n ||
        asBigInt(value.witnessedUnixMillis, 'witnessedUnixMillis') === 0n) {
      fail('external witness revisions, writer epoch, lease, and time must be nonzero')
    }
    const restoreSequence = asBigInt(value.restoreEvidenceHeadSequence, 'restoreEvidenceHeadSequence')
    if ((restoreSequence === 0n) !== isAllZero(value.restoreEvidenceHeadHash)) {
      fail('restore evidence head sequence/hash zero state does not match')
    }
  }
})

export const relayResultBindingV1 = struct([
  ['version', ranged(u8, 1, 1, 'version')],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['durabilityProfileId', ranged(u8, 1, 2, 'durabilityProfileId')],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['restoreEvidenceHeadSequence', u64be],
  ['restoreEvidenceHeadHash', bytes32],
  ['externalCommitWitness', optional(blindExternalCommitWitnessV1, 'externalCommitWitness')]
], {
  name: 'RelayResultBindingV1',
  validate (value) {
    for (const field of [
      'relayPublicKey',
      'storeId',
      'descriptorHash',
      'durabilityContinuityHash',
      'durabilityProfileHash'
    ]) nonzero(value[field], field)
    const restoreSequence = asBigInt(value.restoreEvidenceHeadSequence, 'restoreEvidenceHeadSequence')
    if ((restoreSequence === 0n) !== isAllZero(value.restoreEvidenceHeadHash)) {
      fail('restore evidence head sequence/hash zero state does not match')
    }
    if (value.durabilityProfileId === 1) {
      if (restoreSequence !== 0n || value.externalCommitWitness != null) {
        fail('durability profile 1 forbids restore-head and external-witness state')
      }
      return
    }
    const witness = value.externalCommitWitness
    if (witness == null) return
    for (const field of [
      'relayPublicKey',
      'storeId',
      'durabilityContinuityHash',
      'durabilityProfileHash',
      'restoreEvidenceHeadHash'
    ]) {
      if (!b4a.equals(value[field], witness[field])) fail(`external witness ${field} does not match relay binding`)
    }
    if (asBigInt(value.restoreEvidenceHeadSequence, 'restoreEvidenceHeadSequence') !==
        asBigInt(witness.restoreEvidenceHeadSequence, 'witness restoreEvidenceHeadSequence')) {
      fail('external witness restore evidence sequence does not match relay binding')
    }
  }
})

export const batchGetSignaturePayloadV1 = struct([
  ['version', ranged(u8, 1, 1, 'version')],
  ['relayBinding', relayResultBindingV1],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['entriesCommitment', bytes32]
], { name: 'BatchGetSignaturePayloadV1' })

export const inboxReadSignaturePayloadV1 = struct([
  ['version', ranged(u8, 1, 1, 'version')],
  ['relayBinding', relayResultBindingV1],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['snapshotRevision', u64be],
  ['entriesCommitment', bytes32],
  ['nextCursor', optional(boundedBytes(0, 128, 'nextCursor'), 'nextCursor')]
], { name: 'InboxReadSignaturePayloadV1' })
