import fs from 'node:fs'
import b4a from 'b4a'
import {
  STORE_LIFECYCLE_STATE,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  decodeCanonical,
  durabilityContinuityBindingV1,
  durabilityContinuityHash,
  durabilityProfileHash,
  durabilityProfileV1,
  encodeCanonical,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { ADVERTISED_OPERATION_BITS } from '@hiverelay/blind-protocol/wire-runtime-authority'

const descriptorVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/service-descriptor.bin', import.meta.url))
const parameterVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/admission-parameters.bin', import.meta.url))

export const fixtureBytes = (length, value) => b4a.alloc(length, value)

function clone (codec, value) {
  return decodeCanonical(codec, encodeCanonical(codec, value), { copyBytes: true })
}

export function bindDurability (descriptor) {
  descriptor.durabilityProfileHash = durabilityProfileHash(
    encodeCanonical(durabilityProfileV1, descriptor.durability))
  descriptor.durabilityContinuityHash = durabilityContinuityHash(
    encodeCanonical(durabilityContinuityBindingV1, {
      version: 1,
      profileId: descriptor.durability.profileId,
      externalJournalId: descriptor.durability.externalJournalId,
      externalWitnessPublicKey: descriptor.durability.externalWitnessPublicKey,
      externalJournalReplicationClass: descriptor.durability.externalJournalReplicationClass,
      externalJournalFailureGroupId: descriptor.durability.externalJournalFailureGroupId,
      restoreEvidenceFeedId: descriptor.durability.restoreEvidenceFeedId
    }))
  return descriptor
}

export function descriptorValue (overrides = {}) {
  const value = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true })
  value.endpoints[0].envelopeClassBits = 0x7e
  value.enabledOperationBits = ADVERTISED_OPERATION_BITS
  Object.assign(value, overrides)
  bindDurability(value)
  return value
}

export function descriptorBytes (overrides = {}) {
  return encodeCanonical(blindServiceDescriptorV1, descriptorValue(overrides))
}

export function successorValue (snapshot, overrides = {}) {
  const previous = snapshot.descriptor
  const next = clone(blindServiceDescriptorV1, previous)
  next.descriptorSequence = previous.descriptorSequence + 1n
  next.previousDescriptorHash = b4a.from(snapshot.hash)
  next.issuedEpoch = previous.issuedEpoch + 1
  next.expiresEpoch = previous.expiresEpoch + 1
  next.descriptorNonce = fixtureBytes(32, Number(0x30n + next.descriptorSequence))
  next.signature = fixtureBytes(64, Number(0x50n + next.descriptorSequence))
  Object.assign(next, overrides)
  bindDurability(next)
  return next
}

export function successorBytes (snapshot, overrides = {}) {
  return encodeCanonical(blindServiceDescriptorV1, successorValue(snapshot, overrides))
}

export function parameterValue (relayPublicKey, overrides = {}) {
  const value = decodeCanonical(admissionParametersV1, parameterVector, { copyBytes: true })
  value.relayPublicKey = b4a.from(relayPublicKey)
  Object.assign(value, overrides)
  return value
}

export function parameterBytes (relayPublicKey, overrides = {}) {
  return encodeCanonical(admissionParametersV1, parameterValue(relayPublicKey, overrides))
}

export function descriptorAndParameters (overrides = {}) {
  const relayPublicKey = overrides.relayPublicKey || fixtureBytes(32, 0x71)
  const parameters = parameterBytes(relayPublicKey, overrides.parameters || {})
  const base = descriptorValue({
    relayPublicKey,
    ...(overrides.descriptor || {})
  })
  base.admissionProfiles[0].parameterHash = admissionParametersHash(parameters)
  base.admissionProfiles[0].profileId = 7
  base.admissionProfiles[0].schemeId = 9
  base.admissionProfiles[0].conformanceClass = 1
  base.admissionProfiles[0].roleBits = 1
  bindDurability(base)
  return { descriptor: encodeCanonical(blindServiceDescriptorV1, base), parameters }
}

export function manifestBytes (snapshot, overrides = {}) {
  const descriptor = snapshot.descriptor
  const zero = fixtureBytes(32, 0)
  return encodeCanonical(blindStoreManifestV1, {
    magic: b4a.from('HRBLIND1', 'ascii'),
    manifestVersion: 1,
    storeId: b4a.from(descriptor.storeId),
    relayPublicKey: b4a.from(descriptor.relayPublicKey),
    durabilityProfileId: descriptor.durability.profileId,
    durabilityContinuityHash: b4a.from(descriptor.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(descriptor.durabilityProfileHash),
    formatMajor: descriptor.durability.storeFormatMajor,
    formatMinor: descriptor.durability.storeFormatMinor,
    storeFormatHash: b4a.from(descriptor.durability.storeFormatHash),
    specHash: b4a.from(descriptor.build.specHash),
    abiHash: b4a.from(descriptor.build.abiHash),
    mapGeneration: 1n,
    bucketMapHash: fixtureBytes(32, 0x81),
    checkpointWalSequence: 1n,
    checkpointHash: fixtureBytes(32, 0x82),
    epochFloor: descriptor.issuedEpoch,
    writerEpoch: 1n,
    writerFenceTokenHash: fixtureBytes(32, 0x83),
    externalLeaseRevision: 0n,
    externalJournalId: zero,
    externalWitnessPublicKey: zero,
    restoreEvidenceFeedId: zero,
    lastAckWalSequence: 0n,
    lastAckWalHash: zero,
    externalCheckpointRevision: 0n,
    externalCheckpointHash: zero,
    descriptorSequenceFloor: descriptor.descriptorSequence,
    descriptorHashFloor: serviceDescriptorHash(snapshot.canonicalBytes),
    migrationState: 0,
    sourceFormatMajor: 0,
    targetFormatMajor: 0,
    migrationCursorHash: zero,
    previousManifestHash: null,
    manifestRevision: 0n,
    mac: fixtureBytes(32, 0x84),
    ...overrides
  })
}

export { STORE_LIFECYCLE_STATE }
