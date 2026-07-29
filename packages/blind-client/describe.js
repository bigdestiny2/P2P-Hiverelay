import b4a from 'b4a'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  CLOCK_UNSAFE_OPERATION_BITS,
  DISPATCH_LIMITS,
  FAMILY,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  OPERATION,
  OPERATION_PROFILE_ROWS,
  RESULT_SIGNATURE_DOMAIN_ID,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  operationBit,
  operationProfile
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  admissionParametersHash,
  auxiliarySignaturePayload,
  durabilityContinuityHash,
  durabilityProfileHash,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol/hashes'
import {
  admissionParametersV1,
  blindAdmissionParametersRequestV1,
  blindDescribeGetV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  durabilityProfileV1,
  relayIdentityTransitionV1
} from '@hiverelay/blind-protocol/schemas'
import { encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { smallestOuterClass } from '@hiverelay/blind-protocol/outer-envelope'
import { asBytes, randomBytes } from './bytes.js'
import { fail } from './errors.js'
import { issueVerifiedEndpoint } from './verified-endpoint.js'
import {
  decodeCanonicalCopy,
  sameBytes,
  verifyDetached,
  verifyResultSignedValue
} from './signed.js'

const VERIFIED_DESCRIPTOR = Symbol('VerifiedDescriptor')
const TRUSTED_DESCRIPTOR = Symbol('TrustedDescriptor')
const VERIFIED_HEALTH = Symbol('VerifiedHealth')
const VERIFIED_ADMISSION = Symbol('VerifiedAdmissionParameters')
const MAX_DESCRIPTOR_HISTORY = 4096
const MAX_HEALTH_QUALIFICATION_AGE_MILLIS = 10 * 60 * 1000
const descriptorInternals = new WeakMap()
const trustedInternals = new WeakMap()
const healthInternals = new WeakMap()
const admissionInternals = new WeakMap()

function bytesHex (value) {
  return b4a.toString(value, 'hex')
}

function epoch (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('BAD_CLIENT_INPUT', `${field} is outside u32`)
  }
  return value
}

function monotonicMillis (value, field) {
  if (value == null) {
    value = globalThis.performance && typeof globalThis.performance.now === 'function'
      ? globalThis.performance.now()
      : Date.now()
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('BAD_CLIENT_INPUT', `${field} must be a non-negative finite monotonic timestamp`)
  }
  return value
}

function oneHot (value, field) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff || (value & (value - 1)) !== 0) {
    fail('BAD_CLIENT_INPUT', `${field} must contain exactly one known support bit`)
  }
  return value
}

function knownTransportSupportBit (value) {
  const supportBit = oneHot(value, 'transportSupportBit')
  knownRegistryValue(TRANSPORT_SUPPORT, supportBit, 'transportSupportBit')
  return supportBit
}

function supportedProfiles (values, idField, hashField, label, validate) {
  if (!Array.isArray(values) || values.length === 0) fail('BAD_CLIENT_INPUT', `${label} cannot be empty`)
  const result = new Map()
  for (const value of values) {
    if (!value || !Number.isSafeInteger(value[idField]) || value[idField] < 1 || value[idField] > 0xff) {
      fail('BAD_CLIENT_INPUT', `${label} has an invalid ID`)
    }
    validate(value)
    const hash = b4a.from(asBytes(value[hashField], `${label} hash`, 32))
    if (result.has(value[idField])) fail('BAD_CLIENT_INPUT', `${label} contains a duplicate ID`)
    result.set(value[idField], Object.freeze({ ...value, [hashField]: hash }))
  }
  return result
}

function u16 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    fail('BAD_CLIENT_INPUT', `${field} is outside u16`)
  }
  return value
}

function knownRegistryValue (registry, value, field) {
  if (!Object.values(registry).includes(value)) fail('BAD_CLIENT_INPUT', `${field} is not in the closed registry`)
}

function continuityBinding (durability) {
  return b4a.concat([
    b4a.from([1, durability.profileId]),
    durability.externalJournalId,
    durability.externalWitnessPublicKey,
    b4a.from([durability.externalJournalReplicationClass]),
    durability.externalJournalFailureGroupId,
    durability.restoreEvidenceFeedId
  ])
}

function assertDescriptorHashes (descriptor) {
  const profileBytes = encodeCanonical(durabilityProfileV1, descriptor.durability)
  if (!sameBytes(durabilityProfileHash(profileBytes), descriptor.durabilityProfileHash)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'descriptor durability profile hash is invalid')
  }
  const bindingBytes = continuityBinding(descriptor.durability)
  if (!sameBytes(durabilityContinuityHash(bindingBytes), descriptor.durabilityContinuityHash)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'descriptor durability continuity hash is invalid')
  }
}

function assertCurrentEpoch (value, nowEpoch, label) {
  nowEpoch = epoch(nowEpoch, 'nowEpoch')
  if (nowEpoch < value.issuedEpoch || nowEpoch >= value.expiresEpoch) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} is outside its signed epoch window`)
  }
}

export class VerifiedDescriptor {
  constructor (token, fields) {
    if (token !== VERIFIED_DESCRIPTOR) throw new TypeError('VerifiedDescriptor is not directly constructible')
    descriptorInternals.set(this, fields)
    Object.freeze(this)
  }

  get descriptorHash () { return b4a.from(descriptorInternals.get(this).hash) }
  get descriptorSequence () { return descriptorInternals.get(this).value.descriptorSequence }
  get relayPublicKey () { return b4a.from(descriptorInternals.get(this).value.relayPublicKey) }
  get storeId () { return b4a.from(descriptorInternals.get(this).value.storeId) }
  snapshotBytes () { return b4a.from(descriptorInternals.get(this).bytes) }
}

// A descriptor's predecessor coordinate is needed to prove a current, unnamed
// DESCRIBE head back to an independently authenticated genesis pin. Keep the
// decoded descriptor private: this narrow snapshot exposes only immutable
// linkage/identity fields from an already signature-verified descriptor.
export function verifiedDescriptorLinkage (verified) {
  const fields = verifiedFields(verified)
  const descriptor = fields.value
  return Object.freeze({
    descriptorHash: b4a.from(fields.hash),
    descriptorSequence: BigInt(descriptor.descriptorSequence),
    previousDescriptorHash: descriptor.previousDescriptorHash == null
      ? null
      : b4a.from(descriptor.previousDescriptorHash),
    relayPublicKey: b4a.from(descriptor.relayPublicKey),
    storeId: b4a.from(descriptor.storeId)
  })
}

function verifiedFields (value) {
  const fields = descriptorInternals.get(value)
  if (!fields) fail('BAD_CLIENT_INPUT', 'a VerifiedDescriptor is required')
  return fields
}

export function verifyDescriptorBytes (input, options = {}) {
  const decoded = decodeCanonicalCopy(blindServiceDescriptorV1, input, 'service descriptor')
  const descriptor = decoded.value
  const descriptorHash = serviceDescriptorHash(decoded.bytes)
  if (options.expectedDescriptorHash != null &&
      !sameBytes(descriptorHash, asBytes(options.expectedDescriptorHash, 'expectedDescriptorHash', 32))) {
    fail('RELAY_PROTOCOL_VIOLATION', 'service descriptor hash does not match the requested history object')
  }
  assertDescriptorHashes(descriptor)
  verifyResultSignedValue(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, descriptor.relayPublicKey, 'service descriptor')
  if (options.history !== true) assertCurrentEpoch(descriptor, options.nowEpoch, 'service descriptor')

  const protocols = supportedProfiles(options.supportedProtocolProfiles,
    'protocolId', 'profileHash', 'supported protocol profiles', value => {
      knownRegistryValue(FAMILY, value.protocolId, 'supported protocol ID')
      u16(value.major, 'supported protocol major')
      u16(value.minimumMinor, 'supported protocol minimumMinor')
    })
  const transports = supportedProfiles(options.supportedTransportProfiles,
    'transportId', 'transportProfileHash', 'supported transport profiles', value => {
      knownRegistryValue(TRANSPORT_ID, value.transportId, 'supported transport ID')
      knownRegistryValue(TRANSPORT_SUPPORT, value.transportSupportBit, 'supported transport support bit')
    })
  const descriptorProtocols = new Map(descriptor.protocols.map(value => [value.protocolId, value]))
  for (const [protocolId, supported] of protocols) {
    const advertised = descriptorProtocols.get(protocolId)
    if (advertised && (advertised.major !== supported.major || advertised.minor < supported.minimumMinor ||
        !sameBytes(advertised.profileHash, supported.profileHash))) {
      fail('RELAY_PROTOCOL_VIOLATION', `descriptor protocol ${protocolId} contradicts the pinned profile`)
    }
  }

  return new VerifiedDescriptor(VERIFIED_DESCRIPTOR, {
    bytes: b4a.from(decoded.bytes),
    value: descriptor,
    hash: descriptorHash,
    supportedProtocols: protocols,
    supportedTransports: transports
  })
}

function verifyIdentityTransition (transition, previous, descriptor) {
  const complete = encodeCanonical(relayIdentityTransitionV1, transition)
  const unsigned = complete.subarray(0, complete.byteLength - 128)
  const payload = auxiliarySignaturePayload(AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION, unsigned)
  verifyDetached(previous.relayPublicKey, payload, transition.oldSignature, 'old identity transition')
  verifyDetached(transition.newRelayKey, payload, transition.newSignature, 'new identity transition')
  if (!sameBytes(transition.oldRelayKey, previous.relayPublicKey) ||
      BigInt(transition.oldIdentitySequence) !== BigInt(previous.identitySequence) ||
      BigInt(transition.newIdentitySequence) !== BigInt(previous.identitySequence) + 1n ||
      transition.validFromEpoch !== descriptor.issuedEpoch) {
    fail('DESCRIPTOR_CHAIN_INVALID', 'identity transition does not continue the trusted identity')
  }
}

function copyState (state) {
  if (state == null) return null
  return {
    rootRelayPublicKey: b4a.from(state.rootRelayPublicKey),
    storeId: b4a.from(state.storeId),
    currentBytes: b4a.from(state.currentBytes),
    currentHash: b4a.from(state.currentHash),
    sequence: BigInt(state.sequence),
    identitySequence: BigInt(state.identitySequence),
    relayPublicKey: b4a.from(state.relayPublicKey),
    durabilityProfileId: state.durabilityProfileId,
    durabilityContinuityHash: b4a.from(state.durabilityContinuityHash),
    history: state.history.map(bytes => b4a.from(bytes)),
    quarantined: state.quarantined === true
  }
}

export class MemoryDescriptorTrustBackend {
  constructor () {
    this.records = new Map()
  }

  async read (key) {
    const record = this.records.get(key)
    return record == null ? { version: 0, value: null } : { version: record.version, value: copyState(record.value) }
  }

  async compareAndSwap (key, expectedVersion, value) {
    const current = this.records.get(key)
    const version = current == null ? 0 : current.version
    if (version !== expectedVersion) return false
    this.records.set(key, { version: version + 1, value: copyState(value) })
    return true
  }
}

export class TrustedDescriptor {
  constructor (token, verified, rootRelayPublicKey, trustVersion) {
    if (token !== TRUSTED_DESCRIPTOR) throw new TypeError('TrustedDescriptor is not directly constructible')
    trustedInternals.set(this, {
      verified,
      rootRelayPublicKey: b4a.from(rootRelayPublicKey),
      trustVersion
    })
    Object.freeze(this)
  }

  get descriptorHash () { return b4a.from(verifiedFields(trustedInternals.get(this).verified).hash) }
  get descriptorSequence () { return verifiedFields(trustedInternals.get(this).verified).value.descriptorSequence }
  get rootRelayPublicKey () { return b4a.from(trustedInternals.get(this).rootRelayPublicKey) }
  get trustVersion () { return trustedInternals.get(this).trustVersion }
}

// Validity is deliberately exposed only through the package-owned trust brand.
// Returning a fresh frozen value prevents callers from reaching or mutating the
// decoded signed descriptor held by the continuity store.
export function trustedDescriptorValidity (trusted) {
  const trust = trustedFields(trusted)
  const descriptor = verifiedFields(trust.verified).value
  return Object.freeze({
    issuedEpoch: descriptor.issuedEpoch,
    expiresEpoch: descriptor.expiresEpoch
  })
}

function copyAdmissionProfile (value) {
  return Object.freeze({
    profileId: value.profileId,
    schemeId: value.schemeId,
    conformanceClass: value.conformanceClass,
    roleBits: value.roleBits,
    parameterUrl: value.parameterUrl == null ? null : b4a.from(value.parameterUrl),
    parameterHash: b4a.from(value.parameterHash)
  })
}

export function trustedAdmissionProfile (trusted, profileId) {
  if (!(trusted instanceof TrustedDescriptor)) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  if (!Number.isSafeInteger(profileId) || profileId < 1 || profileId > 0xffff) {
    fail('BAD_CLIENT_INPUT', 'admission profileId is outside u16')
  }
  const trust = trustedFields(trusted)
  const descriptor = verifiedFields(trust.verified).value
  const profile = descriptor.admissionProfiles.find(value => value.profileId === profileId)
  return profile == null ? null : copyAdmissionProfile(profile)
}

function trustedFields (value) {
  const fields = trustedInternals.get(value)
  if (!fields) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  return fields
}

export class DescriptorTrustStore {
  constructor (backend = new MemoryDescriptorTrustBackend()) {
    if (!backend || typeof backend.read !== 'function' || typeof backend.compareAndSwap !== 'function') {
      fail('BAD_CLIENT_INPUT', 'descriptor trust backend must implement read and compareAndSwap')
    }
    this.backend = backend
  }

  async accept (verified, options = {}) {
    if (!(verified instanceof VerifiedDescriptor)) fail('BAD_CLIENT_INPUT', 'a VerifiedDescriptor is required')
    const verifiedState = verifiedFields(verified)
    const descriptor = verifiedState.value
    const descriptorSequence = BigInt(descriptor.descriptorSequence)
    let continuityRoot
    if (descriptorSequence === 0n) {
      continuityRoot = b4a.from(descriptor.relayPublicKey)
      if (options.continuityRootRelayPublicKey != null &&
          !sameBytes(continuityRoot, asBytes(options.continuityRootRelayPublicKey,
            'continuityRootRelayPublicKey', 32))) {
        fail('UNTRUSTED_RELAY_IDENTITY', 'genesis continuity root does not match its relay key')
      }
    } else {
      if (options.continuityRootRelayPublicKey == null) {
        fail('UNTRUSTED_RELAY_IDENTITY', 'descriptor continuation requires its persisted continuity root')
      }
      continuityRoot = b4a.from(asBytes(options.continuityRootRelayPublicKey,
        'continuityRootRelayPublicKey', 32))
    }
    // A relay chooses its own storeId. Keying trust only by that field lets a
    // hostile candidate collide with and quarantine an unrelated operator.
    const key = `descriptor:${bytesHex(continuityRoot)}:${bytesHex(descriptor.storeId)}`
    for (let attempt = 0; attempt < 8; attempt++) {
      const record = await this.backend.read(key)
      const previousState = record.value
      let next
      if (previousState == null) {
        if (descriptorSequence !== 0n || options.pinnedDescriptorHash == null ||
            !sameBytes(verifiedState.hash, asBytes(options.pinnedDescriptorHash, 'pinnedDescriptorHash', 32))) {
          fail('UNTRUSTED_RELAY_IDENTITY', 'descriptor genesis requires an exact authenticated pin')
        }
        next = {
          rootRelayPublicKey: continuityRoot,
          storeId: descriptor.storeId,
          currentBytes: verifiedState.bytes,
          currentHash: verifiedState.hash,
          sequence: 0n,
          identitySequence: BigInt(descriptor.identitySequence),
          relayPublicKey: descriptor.relayPublicKey,
          durabilityProfileId: descriptor.durability.profileId,
          durabilityContinuityHash: descriptor.durabilityContinuityHash,
          history: [verifiedState.bytes],
          quarantined: false
        }
      } else {
        if (previousState.quarantined) fail('DESCRIPTOR_FORK', 'relay continuity is quarantined')
        if (!sameBytes(previousState.rootRelayPublicKey, continuityRoot)) {
          fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor continuation changed its persisted continuity root')
        }
        const sequence = BigInt(descriptor.descriptorSequence)
        if (sequence === previousState.sequence) {
          if (sameBytes(verifiedState.hash, previousState.currentHash)) {
            return new TrustedDescriptor(TRUSTED_DESCRIPTOR, verified,
              previousState.rootRelayPublicKey, record.version)
          }
          next = { ...previousState, quarantined: true }
          if (await this.backend.compareAndSwap(key, record.version, next)) {
            fail('DESCRIPTOR_FORK', 'same-sequence descriptor fork detected and quarantined')
          }
          continue
        }
        if (sequence !== previousState.sequence + 1n || !sameBytes(descriptor.previousDescriptorHash, previousState.currentHash)) {
          fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor does not exactly extend the trusted sequence/hash')
        }
        if (descriptor.durability.profileId !== previousState.durabilityProfileId ||
            !sameBytes(descriptor.durabilityContinuityHash, previousState.durabilityContinuityHash)) {
          fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor changed the trusted durability continuity')
        }
        const sameIdentity = sameBytes(descriptor.relayPublicKey, previousState.relayPublicKey)
        if (sameIdentity) {
          if (BigInt(descriptor.identitySequence) !== previousState.identitySequence ||
              descriptor.previousRelayKey != null || descriptor.identityTransition != null) {
            fail('DESCRIPTOR_CHAIN_INVALID', 'same-key descriptor changed identity continuity')
          }
        } else {
          if (descriptor.identityTransition == null ||
              !sameBytes(descriptor.previousRelayKey, previousState.relayPublicKey) ||
              BigInt(descriptor.identitySequence) !== previousState.identitySequence + 1n) {
            fail('DESCRIPTOR_CHAIN_INVALID', 'relay-key rotation lacks exact dual-signed continuity')
          }
          verifyIdentityTransition(descriptor.identityTransition, previousState, descriptor)
        }
        if (previousState.history.length >= MAX_DESCRIPTOR_HISTORY) {
          fail('DESCRIPTOR_HISTORY_LIMIT', 'descriptor history exceeds 4096 linked objects')
        }
        next = {
          ...previousState,
          currentBytes: verifiedState.bytes,
          currentHash: verifiedState.hash,
          sequence,
          identitySequence: BigInt(descriptor.identitySequence),
          relayPublicKey: descriptor.relayPublicKey,
          history: [...previousState.history, verifiedState.bytes]
        }
      }
      if (await this.backend.compareAndSwap(key, record.version, next)) {
        return new TrustedDescriptor(TRUSTED_DESCRIPTOR, verified, next.rootRelayPublicKey, record.version + 1)
      }
    }
    fail('TRUST_STORE_BUSY', 'descriptor trust CAS did not converge')
  }
}

export class VerifiedHealth {
  constructor (token, fields) {
    if (token !== VERIFIED_HEALTH) throw new TypeError('VerifiedHealth is not directly constructible')
    healthInternals.set(this, fields)
    Object.freeze(this)
  }

  get readyRoleBits () { return healthInternals.get(this).value.readyRoleBits }
  get readyOperationBits () { return healthInternals.get(this).value.readyOperationBits }
}

export function verifiedHealthValidity (health) {
  const fields = healthInternals.get(health)
  if (!fields) fail('BAD_CLIENT_INPUT', 'a VerifiedHealth is required')
  return Object.freeze({
    verifiedAtMonotonicMillis: fields.verifiedAtMonotonicMillis,
    expiresAtMonotonicMillis: fields.verifiedAtMonotonicMillis + MAX_HEALTH_QUALIFICATION_AGE_MILLIS
  })
}

export function verifyHealthResultBytes (input, trusted, challenge, options = {}) {
  if (!(trusted instanceof TrustedDescriptor)) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  const trust = trustedFields(trusted)
  const descriptorState = verifiedFields(trust.verified)
  const decoded = decodeCanonicalCopy(blindHealthResultV1, input, 'health result')
  const value = decoded.value
  const descriptor = descriptorState.value
  verifyResultSignedValue(blindHealthResultV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, descriptor.relayPublicKey, 'health result')
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'durabilityProfileHash']) {
    if (!sameBytes(value[field], descriptor[field])) fail('RELAY_PROTOCOL_VIOLATION', `health ${field} does not match descriptor`)
  }
  if (BigInt(value.descriptorSequence) !== BigInt(descriptor.descriptorSequence) ||
      !sameBytes(value.descriptorHash, descriptorState.hash) || !sameBytes(value.clientNonce, challenge.clientNonce) ||
      value.endpointId !== challenge.endpointId ||
      value.transportSupportBit !== challenge.transportSupportBit) {
    fail('RELAY_PROTOCOL_VIOLATION', 'health result does not correlate to the descriptor challenge')
  }
  if ((value.readyRoleBits & ~challenge.requestedRoleBits) !== 0 ||
      (value.readyOperationBits & ~challenge.requestedOperationBits) !== 0 ||
      (value.readyOperationBits & ~descriptor.enabledOperationBits) !== 0) {
    fail('RELAY_PROTOCOL_VIOLATION', 'health readiness exceeds the challenged or enabled subset')
  }
  const nowEpoch = epoch(options.nowEpoch, 'nowEpoch')
  if (value.challengeEpoch > nowEpoch || nowEpoch - value.challengeEpoch > 1) {
    fail('RELAY_PROTOCOL_VIOLATION', 'health result is stale or future-dated')
  }
  return new VerifiedHealth(VERIFIED_HEALTH, {
    value,
    descriptorHash: b4a.from(descriptorState.hash),
    descriptorSequence: descriptor.descriptorSequence,
    relayPublicKey: b4a.from(descriptor.relayPublicKey),
    storeId: b4a.from(descriptor.storeId),
    verifiedAtMonotonicMillis: monotonicMillis(
      options.observedMonotonicMillis, 'observedMonotonicMillis')
  })
}

export class VerifiedAdmissionParameters {
  constructor (token, value, hash) {
    if (token !== VERIFIED_ADMISSION) throw new TypeError('VerifiedAdmissionParameters is not directly constructible')
    admissionInternals.set(this, { value, hash })
    Object.freeze(this)
  }

  get parameterHash () { return b4a.from(admissionInternals.get(this).hash) }
}

export function verifiedAdmissionParametersValidity (verified) {
  const fields = admissionInternals.get(verified)
  if (!fields) fail('BAD_CLIENT_INPUT', 'VerifiedAdmissionParameters are required')
  return Object.freeze({
    validFromEpoch: fields.value.validFromEpoch,
    expiresEpoch: fields.value.expiresEpoch
  })
}

export function verifyAdmissionParametersBytes (input, trusted, requestedProfile, options = {}) {
  if (!(trusted instanceof TrustedDescriptor)) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  const trust = trustedFields(trusted)
  const decoded = decodeCanonicalCopy(admissionParametersV1, input, 'admission parameters')
  const value = decoded.value
  const descriptor = verifiedFields(trust.verified).value
  const hash = admissionParametersHash(decoded.bytes)
  verifyResultSignedValue(admissionParametersV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, descriptor.relayPublicKey, 'admission parameters')
  if (!requestedProfile || !Number.isSafeInteger(requestedProfile.profileId)) {
    fail('BAD_CLIENT_INPUT', 'requested admission profile is invalid')
  }
  const advertised = descriptor.admissionProfiles.find(profile => profile.profileId === requestedProfile.profileId)
  const sameOptionalUrl = advertised != null &&
    ((advertised.parameterUrl == null && requestedProfile.parameterUrl == null) ||
      (advertised.parameterUrl != null && requestedProfile.parameterUrl != null &&
       sameBytes(advertised.parameterUrl, requestedProfile.parameterUrl)))
  if (!advertised || value.profileId !== advertised.profileId || value.schemeId !== advertised.schemeId ||
      value.conformanceClass !== advertised.conformanceClass || value.roleBits !== advertised.roleBits ||
      requestedProfile.schemeId !== advertised.schemeId ||
      requestedProfile.conformanceClass !== advertised.conformanceClass ||
      requestedProfile.roleBits !== advertised.roleBits || !sameOptionalUrl ||
      !sameBytes(requestedProfile.parameterHash, advertised.parameterHash) ||
      !sameBytes(value.relayPublicKey, descriptor.relayPublicKey) || !sameBytes(hash, advertised.parameterHash)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'admission parameters do not match the signed descriptor profile')
  }
  const nowEpoch = epoch(options.nowEpoch, 'nowEpoch')
  if (nowEpoch < value.validFromEpoch || nowEpoch >= value.expiresEpoch) {
    fail('RELAY_PROTOCOL_VIOLATION', 'admission parameters are outside their signed epoch window')
  }
  return new VerifiedAdmissionParameters(VERIFIED_ADMISSION, value, hash)
}

function qualificationAuthority (options) {
  const trusted = options && options.trustedDescriptor
  if (!(trusted instanceof TrustedDescriptor)) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  const trust = trustedFields(trusted)
  const descriptorState = verifiedFields(trust.verified)
  const descriptor = descriptorState.value
  const nowEpoch = epoch(options.nowEpoch, 'nowEpoch')
  if (nowEpoch < descriptor.issuedEpoch || nowEpoch >= descriptor.expiresEpoch ||
      descriptor.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED) {
    fail('RELAY_NOT_QUALIFIED', 'descriptor is expired or retired')
  }
  const profile = operationProfile(options.familyId, options.operationId)
  const bit = operationBit(options.familyId, options.operationId)
  if (!profile || bit === 0 || (descriptor.enabledOperationBits & bit) === 0) {
    fail('RELAY_NOT_QUALIFIED', 'operation is not enabled by the trusted descriptor')
  }
  const advertisedProtocol = descriptor.protocols.find(value => value.protocolId === options.familyId)
  const supportedProtocol = descriptorState.supportedProtocols.get(options.familyId)
  if (!advertisedProtocol || !supportedProtocol || advertisedProtocol.major !== supportedProtocol.major ||
      advertisedProtocol.minor < supportedProtocol.minimumMinor ||
      !sameBytes(advertisedProtocol.profileHash, supportedProtocol.profileHash)) {
    fail('RELAY_NOT_QUALIFIED', 'operation family has no pinned compatible protocol profile')
  }
  const endpoint = descriptor.endpoints.find(value => value.endpointId === options.endpointId)
  if (!endpoint) fail('RELAY_NOT_QUALIFIED', 'endpoint is absent from the trusted descriptor')
  const supportedTransport = descriptorState.supportedTransports.get(endpoint.transportId)
  const transportSupportBit = knownTransportSupportBit(options.transportSupportBit)
  if (!supportedTransport || !sameBytes(endpoint.transportProfileHash, supportedTransport.transportProfileHash) ||
      supportedTransport.transportSupportBit !== transportSupportBit ||
      (profile.transportSupportBits & transportSupportBit) === 0) {
    fail('RELAY_NOT_QUALIFIED', 'endpoint transport profile is not pinned for this operation')
  }
  if ((transportSupportBit & (TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.OHTTP |
      TRANSPORT_SUPPORT.TOR_HTTP)) !== 0) {
    const prefix = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
    const requiredOuterClass = smallestOuterClass(Math.max(
      prefix + profile.maxRequestBodyBytes,
      prefix + profile.maxResultBodyBytes
    ))
    if ((endpoint.envelopeClassBits & (1 << requiredOuterClass)) === 0) {
      fail('RELAY_NOT_QUALIFIED', 'endpoint cannot carry the operation maximum in a signed outer class')
    }
  }
  const requiredRoleBits = options.requiredRoleBits
  const privacyProfileBit = oneHot(options.privacyProfileBit, 'privacyProfileBit')
  if (!Number.isSafeInteger(requiredRoleBits) || requiredRoleBits <= 0 ||
      (endpoint.roleBits & requiredRoleBits) !== requiredRoleBits ||
      (endpoint.privacyProfileBits & privacyProfileBit) === 0) {
    fail('RELAY_NOT_QUALIFIED', 'endpoint lacks the requested role or privacy profile')
  }
  return {
    trust,
    descriptorState,
    descriptor,
    endpoint,
    bit,
    requiredRoleBits,
    transportSupportBit,
    privacyProfileBit
  }
}

function issueQualifiedEndpoint (options, authority) {
  const { trust, descriptorState, descriptor, endpoint, transportSupportBit, privacyProfileBit } = authority
  return issueVerifiedEndpoint({
    endpoint,
    descriptorHash: descriptorState.hash,
    descriptorSequence: descriptor.descriptorSequence,
    relayPublicKey: descriptor.relayPublicKey,
    storeId: descriptor.storeId,
    continuityRoot: trust.rootRelayPublicKey,
    familyId: options.familyId,
    operationId: options.operationId,
    transportSupportBit,
    privacyProfileBit,
    durabilityProfileId: descriptor.durability.profileId,
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    restoreEvidenceHeadSequence: descriptor.durability.restoreEvidenceCheckpointSequence,
    restoreEvidenceHeadHash: descriptor.durability.restoreEvidenceCheckpointHash,
    externalWitnessPublicKey: descriptor.durability.externalWitnessPublicKey,
    externalJournalId: descriptor.durability.externalJournalId
  })
}

// Health qualification cannot itself require a health-qualified endpoint. This
// issuer breaks that cycle without exposing a raw ordinary-operation bypass: it
// accepts only the three DESCRIBE control operations and binds the resulting
// handle to an already trusted, current signed descriptor.
export function qualifyDescribeControlEndpoint (options) {
  if (!options || options.familyId !== FAMILY.DESCRIBE ||
      ![OPERATION.DESCRIBE.GET, OPERATION.DESCRIBE.CHALLENGE,
        OPERATION.DESCRIBE.ADMISSION_PARAMETERS].includes(options.operationId)) {
    fail('BAD_CLIENT_INPUT', 'control qualification accepts only a DESCRIBE operation')
  }
  return issueQualifiedEndpoint(options, qualificationAuthority(options))
}

export function qualifyRelay (options) {
  const authority = qualificationAuthority(options)
  const { descriptorState, descriptor, bit, requiredRoleBits } = authority
  const nowEpoch = epoch(options.nowEpoch, 'nowEpoch')
  const health = options.health
  const healthState = healthInternals.get(health)
  const healthValue = healthState && healthState.value
  const nowMonotonicMillis = monotonicMillis(options.nowMonotonicMillis, 'nowMonotonicMillis')
  const healthAgeMillis = healthState == null
    ? Number.POSITIVE_INFINITY
    : nowMonotonicMillis - healthState.verifiedAtMonotonicMillis
  if (!(health instanceof VerifiedHealth) ||
      healthAgeMillis < 0 || healthAgeMillis > MAX_HEALTH_QUALIFICATION_AGE_MILLIS ||
      !sameBytes(healthState.descriptorHash, descriptorState.hash) ||
      BigInt(healthState.descriptorSequence) !== BigInt(descriptor.descriptorSequence) ||
      !sameBytes(healthState.relayPublicKey, descriptor.relayPublicKey) ||
      !sameBytes(healthState.storeId, descriptor.storeId) ||
      healthValue.endpointId !== authority.endpoint.endpointId ||
      healthValue.transportSupportBit !== authority.transportSupportBit ||
      (healthValue.readyRoleBits & requiredRoleBits) !== requiredRoleBits ||
      (healthValue.readyOperationBits & bit) !== bit ||
      healthValue.clockState !== HEALTH_CLOCK_STATE.READY ||
      healthValue.integrityState !== HEALTH_INTEGRITY_STATE.VERIFIED ||
      ((bit & CLOCK_UNSAFE_OPERATION_BITS) !== 0 && healthValue.effectiveEpochFloor > nowEpoch)) {
    fail('RELAY_NOT_QUALIFIED', 'fresh health does not prove requested readiness')
  }
  return issueQualifiedEndpoint(options, authority)
}

function nonce (runtime, value, label) {
  return value == null ? randomBytes(runtime, 32, label) : b4a.from(asBytes(value, label, 32))
}

export function createDescribeGetRequest (options = {}) {
  const request = {
    version: 1,
    descriptorHash: options.descriptorHash == null ? null : b4a.from(asBytes(options.descriptorHash, 'descriptorHash', 32)),
    clientNonce: nonce(options.runtime, options.clientNonce, 'describe client nonce')
  }
  return {
    request,
    requestBytes: encodeCanonical(blindDescribeGetV1, request),
    wire: Object.freeze({ familyId: FAMILY.DESCRIBE, operationId: OPERATION.DESCRIBE.GET, expectedResultBodyBytes: 16384 })
  }
}

export function createHealthChallenge (options) {
  const trusted = options && options.trustedDescriptor
  if (!(trusted instanceof TrustedDescriptor)) fail('BAD_CLIENT_INPUT', 'a TrustedDescriptor is required')
  const descriptorState = verifiedFields(trustedFields(trusted).verified)
  const descriptor = descriptorState.value
  const endpointId = options.endpointId
  if (!Number.isSafeInteger(endpointId) || endpointId < 1 || endpointId > 0xff) {
    fail('BAD_CLIENT_INPUT', 'endpointId is outside 1..255')
  }
  const transportSupportBit = knownTransportSupportBit(options.transportSupportBit)
  const endpoint = descriptor.endpoints.find(value => value.endpointId === endpointId)
  const supportedTransport = endpoint == null ? null : descriptorState.supportedTransports.get(endpoint.transportId)
  if (!endpoint || !supportedTransport ||
      !sameBytes(endpoint.transportProfileHash, supportedTransport.transportProfileHash) ||
      supportedTransport.transportSupportBit !== transportSupportBit) {
    fail('RELAY_NOT_QUALIFIED', 'health challenge endpoint transport is not pinned by the trusted descriptor')
  }
  if (!Number.isSafeInteger(options.requestedRoleBits) || options.requestedRoleBits <= 0 ||
      (options.requestedRoleBits & ~endpoint.roleBits) !== 0 ||
      !Number.isSafeInteger(options.requestedOperationBits) || options.requestedOperationBits <= 0 ||
      (options.requestedOperationBits & ~descriptor.enabledOperationBits) !== 0) {
    fail('RELAY_NOT_QUALIFIED', 'health challenge exceeds the endpoint role or descriptor operation set')
  }
  for (let ordinal = 0; ordinal < OPERATION_PROFILE_ROWS.length; ordinal++) {
    const operationBit = 1 << ordinal
    if ((options.requestedOperationBits & operationBit) !== 0 &&
        (OPERATION_PROFILE_ROWS[ordinal].transportSupportBits & transportSupportBit) === 0) {
      fail('RELAY_NOT_QUALIFIED', 'health challenge operation is unsupported by the bound endpoint transport')
    }
  }
  const request = {
    version: 1,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash: descriptorState.hash,
    endpointId,
    transportSupportBit,
    requestedRoleBits: options.requestedRoleBits,
    requestedOperationBits: options.requestedOperationBits,
    clientNonce: nonce(options.runtime, options.clientNonce, 'health client nonce')
  }
  return {
    request,
    requestBytes: encodeCanonical(blindHealthChallengeV1, request),
    wire: Object.freeze({ familyId: FAMILY.DESCRIBE, operationId: OPERATION.DESCRIBE.CHALLENGE, expectedResultBodyBytes: 16384 })
  }
}

export function createAdmissionParametersRequest (options) {
  const request = {
    version: 1,
    profileId: options.profileId,
    schemeId: options.schemeId,
    clientNonce: nonce(options.runtime, options.clientNonce, 'admission client nonce')
  }
  return {
    request,
    requestBytes: encodeCanonical(blindAdmissionParametersRequestV1, request),
    wire: Object.freeze({
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.ADMISSION_PARAMETERS,
      expectedResultBodyBytes: 16384
    })
  }
}

export const HEALTH_QUALIFICATION_LIMITS = Object.freeze({
  maximumAgeMillis: MAX_HEALTH_QUALIFICATION_AGE_MILLIS
})
