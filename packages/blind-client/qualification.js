import b4a from 'b4a'
import {
  FAMILY,
  OPERATION,
  operationBit
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { asBytes } from './bytes.js'
import { BlindDescriptorBootstrapHttpClient } from './bootstrap-http.js'
import {
  DescriptorTrustStore,
  createHealthChallenge,
  qualifyDescribeControlEndpoint,
  qualifyRelay,
  verifyHealthResultBytes
} from './describe.js'
import { BlindDirectHttpClient } from './direct-http.js'
import { fail } from './errors.js'

function epoch (value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('BAD_CLIENT_INPUT', 'nowEpoch is outside u32')
  }
  return value
}

function requirement (value) {
  if (!value || typeof value !== 'object') fail('BAD_CLIENT_INPUT', 'qualification requirement is required')
  const bit = operationBit(value.familyId, value.operationId)
  if (bit === 0) fail('BAD_CLIENT_INPUT', 'qualification operation is not registered')
  for (const field of ['endpointId', 'requiredRoleBits', 'privacyProfileBit', 'transportSupportBit']) {
    if (!Number.isSafeInteger(value[field]) || value[field] <= 0) {
      fail('BAD_CLIENT_INPUT', `qualification ${field} is invalid`)
    }
  }
  return { ...value, operationBit: bit }
}

function profilePins (values, hashField, label) {
  return Object.freeze(values.map((value, index) => Object.freeze({
    ...value,
    [hashField]: b4a.from(asBytes(value && value[hashField], `${label}[${index}].${hashField}`, 32))
  })))
}

function currentMonotonicMillis () {
  return globalThis.performance && typeof globalThis.performance.now === 'function'
    ? globalThis.performance.now()
    : Date.now()
}

// One bounded qualification attempt. Candidate discovery and source diversity
// stay outside this class; every app can feed it DHT, directory, peer, release-pin
// or user-pin candidates without granting any source relay-membership authority.
export class BlindRelayQualifier {
  constructor (options = {}) {
    this.runtime = options.runtime
    this.nowEpoch = typeof options.nowEpoch === 'function' ? options.nowEpoch : null
    if (!this.nowEpoch) fail('BAD_CLIENT_INPUT', 'nowEpoch provider is required')
    this.monotonicMillis = typeof options.monotonicMillis === 'function'
      ? options.monotonicMillis
      : currentMonotonicMillis
    if (!Array.isArray(options.supportedProtocolProfiles) ||
        !Array.isArray(options.supportedTransportProfiles)) {
      fail('BAD_CLIENT_INPUT', 'supported protocol and transport profile pins are required')
    }
    this.supportedProtocolProfiles = profilePins(
      options.supportedProtocolProfiles, 'profileHash', 'supportedProtocolProfiles')
    this.supportedTransportProfiles = profilePins(
      options.supportedTransportProfiles, 'transportProfileHash', 'supportedTransportProfiles')
    this.trustStore = options.trustStore || new DescriptorTrustStore()
    this.bootstrapClient = options.bootstrapClient || new BlindDescriptorBootstrapHttpClient({
      runtime: this.runtime,
      fetch: options.fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    this.directClient = options.directClient || new BlindDirectHttpClient({
      runtime: this.runtime,
      fetch: options.fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
  }

  async qualifyCandidate (candidate, requested, options = {}) {
    if (!candidate || typeof candidate !== 'object') fail('BAD_CLIENT_INPUT', 'relay candidate is required')
    const needed = requirement(requested)
    const nowEpoch = epoch(this.nowEpoch())
    const expectedDescriptorHash = b4a.from(asBytes(
      candidate.expectedDescriptorHash, 'candidate expectedDescriptorHash', 32))
    const canonicalUrl = b4a.from(asBytes(candidate.canonicalUrl, 'candidate canonicalUrl'))
    const continuityRootRelayPublicKey = candidate.continuityRootRelayPublicKey == null
      ? null
      : b4a.from(asBytes(candidate.continuityRootRelayPublicKey,
        'candidate continuityRootRelayPublicKey', 32))
    const verifiedDescriptor = await this.bootstrapClient.fetchVerifiedDescriptor({
      canonicalUrl,
      expectedDescriptorHash,
      nowEpoch,
      supportedProtocolProfiles: this.supportedProtocolProfiles,
      supportedTransportProfiles: this.supportedTransportProfiles,
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
    const acceptOptions = verifiedDescriptor.descriptorSequence === 0n
      ? {
          pinnedDescriptorHash: expectedDescriptorHash,
          continuityRootRelayPublicKey
        }
      : {
          continuityRootRelayPublicKey
        }
    const trustedDescriptor = await this.trustStore.accept(verifiedDescriptor, acceptOptions)
    const challenge = createHealthChallenge({
      runtime: this.runtime,
      trustedDescriptor,
      endpointId: needed.endpointId,
      transportSupportBit: needed.transportSupportBit,
      requestedRoleBits: needed.requiredRoleBits,
      requestedOperationBits: needed.operationBit
    })
    const controlEndpoint = qualifyDescribeControlEndpoint({
      trustedDescriptor,
      nowEpoch,
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.CHALLENGE,
      endpointId: needed.endpointId,
      requiredRoleBits: needed.requiredRoleBits,
      privacyProfileBit: needed.privacyProfileBit,
      transportSupportBit: needed.transportSupportBit
    })
    const healthResult = await this.directClient.request({
      endpoint: controlEndpoint,
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.CHALLENGE,
      expectedResultBodyBytes: challenge.wire.expectedResultBodyBytes,
      body: challenge.requestBytes,
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
    if (!healthResult.ok) fail('RELAY_NOT_QUALIFIED', 'relay rejected its signed health challenge')
    const healthObservedMonotonicMillis = this.monotonicMillis()
    const health = verifyHealthResultBytes(
      healthResult.body,
      trustedDescriptor,
      challenge.request,
      { nowEpoch, observedMonotonicMillis: healthObservedMonotonicMillis }
    )
    const endpoint = qualifyRelay({
      trustedDescriptor,
      health,
      nowEpoch,
      nowMonotonicMillis: healthObservedMonotonicMillis,
      familyId: needed.familyId,
      operationId: needed.operationId,
      endpointId: needed.endpointId,
      requiredRoleBits: needed.requiredRoleBits,
      privacyProfileBit: needed.privacyProfileBit,
      transportSupportBit: needed.transportSupportBit
    })
    return Object.freeze({
      endpoint,
      trustedDescriptor,
      verifiedDescriptor,
      health,
      descriptorHash: verifiedDescriptor.descriptorHash,
      continuityRootRelayPublicKey: trustedDescriptor.rootRelayPublicKey
    })
  }
}
