import b4a from 'b4a'
import { TRANSPORT_SUPPORT } from '@hiverelay/blind-protocol/registry'
import { issueVerifiedEndpoint } from '../verified-endpoint.js'

// Test-only issuer. The package manifest excludes test/, and the production
// exports map exposes no route to the internal VerifiedEndpoint issuer.
export function verifiedEndpointFixture (endpoint, familyId, operationId, overrides = {}) {
  return issueVerifiedEndpoint({
    endpoint: {
      transportProfileHash: b4a.alloc(32, 0x90),
      endpointKey: null,
      auxiliaryUrl: null,
      auxiliaryHash: null,
      ...endpoint
    },
    descriptorHash: b4a.alloc(32, 0x91),
    descriptorSequence: 0n,
    relayPublicKey: b4a.alloc(32, 0x92),
    storeId: b4a.alloc(32, 0x93),
    continuityRoot: b4a.alloc(32, 0x94),
    familyId,
    operationId,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    privacyProfileBit: 1,
    durabilityProfileId: 1,
    durabilityContinuityHash: b4a.alloc(32, 0x95),
    durabilityProfileHash: b4a.alloc(32, 0x96),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalWitnessPublicKey: b4a.alloc(32),
    externalJournalId: b4a.alloc(32),
    ...overrides
  })
}
