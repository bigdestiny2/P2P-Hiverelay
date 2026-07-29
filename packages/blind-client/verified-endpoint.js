import b4a from 'b4a'
import { fail } from './errors.js'

const VERIFIED_ENDPOINT = Symbol('VerifiedEndpoint')
const endpointInternals = new WeakMap()

export class VerifiedEndpoint {
  constructor (token, fields) {
    if (token !== VERIFIED_ENDPOINT) throw new TypeError('VerifiedEndpoint is not directly constructible')
    endpointInternals.set(this, fields)
    Object.freeze(this)
  }

  get relayPublicKey () { return b4a.from(endpointInternals.get(this).relayPublicKey) }
  get descriptorHash () { return b4a.from(endpointInternals.get(this).descriptorHash) }
  get familyId () { return endpointInternals.get(this).familyId }
  get operationId () { return endpointInternals.get(this).operationId }
}

// Internal package issuer. This file is deliberately absent from package.json
// exports; only the authenticated descriptor qualifier can reach this function.
export function issueVerifiedEndpoint (fields) {
  return new VerifiedEndpoint(VERIFIED_ENDPOINT, fields)
}

export function unwrapVerifiedEndpoint (value) {
  const fields = endpointInternals.get(value)
  if (!fields) return null
  const endpoint = fields.endpoint
  return {
    ...endpoint,
    qualifiedFamilyId: fields.familyId,
    qualifiedOperationId: fields.operationId,
    transportSupportBit: fields.transportSupportBit,
    transportProfileHash: b4a.from(endpoint.transportProfileHash),
    canonicalUrl: b4a.from(endpoint.canonicalUrl),
    endpointKey: endpoint.endpointKey == null ? null : b4a.from(endpoint.endpointKey),
    auxiliaryUrl: endpoint.auxiliaryUrl == null ? null : b4a.from(endpoint.auxiliaryUrl),
    auxiliaryHash: endpoint.auxiliaryHash == null ? null : b4a.from(endpoint.auxiliaryHash)
  }
}

export function verifiedEndpointContext (value) {
  const fields = endpointInternals.get(value)
  if (!fields) fail('BAD_CLIENT_INPUT', 'a VerifiedEndpoint is required')
  return Object.freeze({
    descriptorHash: b4a.from(fields.descriptorHash),
    descriptorSequence: fields.descriptorSequence,
    relayPublicKey: b4a.from(fields.relayPublicKey),
    storeId: b4a.from(fields.storeId),
    continuityRoot: b4a.from(fields.continuityRoot),
    familyId: fields.familyId,
    operationId: fields.operationId,
    endpointId: fields.endpoint.endpointId,
    transportId: fields.endpoint.transportId,
    transportSupportBit: fields.transportSupportBit,
    privacyProfileBit: fields.privacyProfileBit,
    durabilityProfileId: fields.durabilityProfileId,
    durabilityContinuityHash: b4a.from(fields.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(fields.durabilityProfileHash),
    restoreEvidenceHeadSequence: fields.restoreEvidenceHeadSequence,
    restoreEvidenceHeadHash: b4a.from(fields.restoreEvidenceHeadHash),
    externalWitnessPublicKey: b4a.from(fields.externalWitnessPublicKey),
    externalJournalId: b4a.from(fields.externalJournalId)
  })
}
