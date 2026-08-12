import { BlindDescriptorBootstrapHttpClient as AcceptedBootstrapClient } from '../../blind-client/bootstrap-http.js'
import { BlindDirectHttpClient as AcceptedDirectClient } from '../../blind-client/direct-http.js'
import { BlindRelayQualifier as AcceptedRelayQualifier } from '../../blind-client/qualification.js'

export {
  CLIENT_SELECTION_LIMITS,
  DescriptorTrustStore,
  DurabilityTracker,
  DurableAttempt,
  EncryptedIntentStore,
  HEALTH_QUALIFICATION_LIMITS,
  INTENT_STATE,
  MemoryDescriptorTrustBackend,
  MemoryIntentBackend,
  RESULT_VERIFIER_STATUS,
  RelayCandidatePool,
  TrustedDescriptor,
  VerifiedAdmissionParameters,
  VerifiedDescriptor,
  VerifiedEndpoint,
  VerifiedHealth,
  VerifiedOperationResult,
  createAdmissionParametersRequest,
  createAesGcmIntentSealer,
  createCellReplica,
  createClientIntent,
  createDescribeGetRequest,
  createGetCellRequest,
  createHealthChallenge,
  decodeBlindExternalProfileValueV1,
  decodeClientIntent,
  encodeClientIntent,
  journalSignedIntent,
  openVerifiedCellGetResult,
  qualifyDescribeControlEndpoint,
  qualifyRelay,
  trustedAdmissionProfile,
  trustedDescriptorValidity,
  verifiedAdmissionParametersValidity,
  verifiedEndpointContext,
  verifiedHealthValidity,
  verifyAdmissionParametersBytes,
  verifyDescriptorBytes,
  verifyHealthResultBytes,
  verifyOperationResult
} from '../../blind-client/control.js'
export { createBrowserCryptoRuntime } from '../../blind-client/runtime/browser.js'
export {
  createAppendInboxRequest,
  createReadInboxRequest
} from '../../blind-client/inbox.js'

function boundFetch (options) {
  return options.fetch ||
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : globalThis.fetch)
}

export class BlindDescriptorBootstrapHttpClient extends AcceptedBootstrapClient {
  constructor (options = {}) {
    super({ ...options, fetch: boundFetch(options) })
  }
}

export class BlindDirectHttpClient extends AcceptedDirectClient {
  constructor (options = {}) {
    super({ ...options, fetch: boundFetch(options) })
  }
}

export class BlindRelayQualifier extends AcceptedRelayQualifier {
  constructor (options = {}) {
    const fetch = boundFetch(options)
    super({
      ...options,
      fetch,
      bootstrapClient: options.bootstrapClient || new BlindDescriptorBootstrapHttpClient({
        runtime: options.runtime,
        fetch,
        allowInsecureLoopback: options.allowInsecureLoopback
      }),
      directClient: options.directClient || new BlindDirectHttpClient({
        runtime: options.runtime,
        fetch,
        allowInsecureLoopback: options.allowInsecureLoopback
      })
    })
  }
}
