import b4a from 'b4a'
import {
  FAMILY,
  OPERATION
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { asBytes } from './bytes.js'
import { BlindDescriptorBootstrapHttpClient } from './bootstrap-http.js'
import {
  DescriptorTrustStore,
  trustedAdmissionProfile,
  trustedDescriptorValidity,
  verifiedDescriptorLinkage
} from './describe.js'
import { BlindDirectHttpClient } from './direct-http.js'
import { fail } from './errors.js'
import { BlindRelayQualifier } from './qualification.js'
import { createGetCellRequest } from './cell-get-requests.js'
import {
  openVerifiedCellGetResult,
  verifyCellGetResult
} from './cell-get-results.js'
import { verifiedEndpointContext } from './verified-endpoint.js'
import { createBrowserCryptoRuntime } from './runtime/browser.js'

const CONTROL_INTERNALS = new WeakMap()
const FORBIDDEN_OPERATION_FIELDS = Object.freeze([
  'familyId',
  'operationId',
  'requested',
  'body',
  'expectedResultBodyBytes',
  'outerClass'
])

function controlInternals (value) {
  const internal = CONTROL_INTERNALS.get(value)
  if (!internal) fail('BAD_CLIENT_INPUT', 'a package-owned BlindCellGetControl is required')
  return internal
}

function rejectOperationSelection (value, label) {
  if (!value || typeof value !== 'object') fail('BAD_CLIENT_INPUT', `${label} options are required`)
  const supplied = FORBIDDEN_OPERATION_FIELDS.filter(field =>
    Object.prototype.hasOwnProperty.call(value, field))
  if (supplied.length > 0) {
    fail('BAD_CLIENT_INPUT', `${label} cannot select a family, operation, body, or envelope class`)
  }
}

function profilePins (values, hashField, label) {
  if (!Array.isArray(values) || values.length === 0) {
    fail('BAD_CLIENT_INPUT', `${label} pins are required`)
  }
  return Object.freeze(values.map((value, index) => Object.freeze({
    ...value,
    [hashField]: b4a.from(asBytes(
      value && value[hashField], `${label}[${index}].${hashField}`, 32))
  })))
}

function descriptorOptions (internal, options, history) {
  if (!options || typeof options !== 'object') {
    fail('BAD_CLIENT_INPUT', 'descriptor bootstrap options are required')
  }
  const output = {
    canonicalUrl: options.canonicalUrl,
    clientNonce: options.clientNonce,
    requestId: options.requestId,
    nowEpoch: internal.nowEpoch(),
    supportedProtocolProfiles: internal.supportedProtocolProfiles,
    supportedTransportProfiles: internal.supportedTransportProfiles,
    timeoutMillis: options.timeoutMillis,
    signal: options.signal
  }
  if (history) {
    output.expectedDescriptorHash = options.expectedDescriptorHash
    output.history = true
  }
  return output
}

// This object is the complete browser capability boundary for public seed
// recovery. Its only network operations are DESCRIBE.GET,
// DESCRIBE.CHALLENGE, and CELL.GET. Generic transport and qualification
// objects remain private and are never returned to the caller.
class BlindCellGetControl {
  constructor (options = {}) {
    if (typeof options.nowEpoch !== 'function') {
      fail('BAD_CLIENT_INPUT', 'nowEpoch provider is required')
    }
    const supportedProtocolProfiles = profilePins(
      options.supportedProtocolProfiles, 'profileHash', 'supportedProtocolProfiles')
    const supportedTransportProfiles = profilePins(
      options.supportedTransportProfiles, 'transportProfileHash', 'supportedTransportProfiles')
    const trustStore = new DescriptorTrustStore()
    const bootstrapClient = new BlindDescriptorBootstrapHttpClient({
      runtime: options.runtime,
      fetch: options.fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    const directClient = new BlindDirectHttpClient({
      runtime: options.runtime,
      fetch: options.fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    const qualifier = new BlindRelayQualifier({
      runtime: options.runtime,
      nowEpoch: options.nowEpoch,
      monotonicMillis: options.monotonicMillis,
      supportedProtocolProfiles,
      supportedTransportProfiles,
      trustStore,
      bootstrapClient,
      directClient
    })
    CONTROL_INTERNALS.set(this, Object.freeze({
      runtime: options.runtime,
      nowEpoch: options.nowEpoch,
      supportedProtocolProfiles,
      supportedTransportProfiles,
      trustStore,
      bootstrapClient,
      directClient,
      qualifier
    }))
    Object.freeze(this)
  }

  async fetchDescriptorHead (options) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'descriptor head')
    return internal.bootstrapClient.fetchVerifiedDescriptorHead(
      descriptorOptions(internal, options, false))
  }

  async fetchDescriptorHistory (options) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'descriptor history')
    return internal.bootstrapClient.fetchVerifiedDescriptor(
      descriptorOptions(internal, options, true))
  }

  descriptorLinkage (verifiedDescriptor) {
    controlInternals(this)
    return verifiedDescriptorLinkage(verifiedDescriptor)
  }

  async acceptDescriptor (verifiedDescriptor, options = {}) {
    const internal = controlInternals(this)
    return internal.trustStore.accept(verifiedDescriptor, {
      pinnedDescriptorHash: options.pinnedDescriptorHash,
      continuityRootRelayPublicKey: options.continuityRootRelayPublicKey
    })
  }

  trustedDescriptorValidity (trustedDescriptor) {
    controlInternals(this)
    return trustedDescriptorValidity(trustedDescriptor)
  }

  trustedAdmissionProfile (trustedDescriptor, profileId) {
    controlInternals(this)
    return trustedAdmissionProfile(trustedDescriptor, profileId)
  }

  async qualifyCellGetCandidate (candidate, options = {}) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'Cell GET qualification')
    return internal.qualifier.qualifyCandidate(candidate, {
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      endpointId: options.endpointId,
      requiredRoleBits: options.requiredRoleBits,
      privacyProfileBit: options.privacyProfileBit,
      transportSupportBit: options.transportSupportBit
    }, {
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
  }

  endpointContext (endpoint) {
    controlInternals(this)
    const context = verifiedEndpointContext(endpoint)
    if (context.familyId !== FAMILY.CELL || context.operationId !== OPERATION.CELL.GET) {
      fail('BAD_CLIENT_INPUT', 'qualified endpoint is not CELL.GET')
    }
    return context
  }

  async readCell (options) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'Cell GET')
    const endpointContext = this.endpointContext(options.endpoint)
    const request = await createGetCellRequest({
      runtime: internal.runtime,
      readCap: options.readCap,
      clientNonce: options.clientNonce,
      admission: options.admission,
      admissionProvider: options.admissionProvider
    })
    const result = await internal.directClient.request({
      endpoint: options.endpoint,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      expectedResultBodyBytes: request.wire.expectedResultBodyBytes,
      body: request.requestBytes,
      requestId: options.requestId,
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
    if (!result.ok) fail('TRANSPORT_FAILURE', 'relay rejected CELL.GET')
    const verifiedResult = verifyCellGetResult({
      endpoint: options.endpoint,
      request: request.request,
      requestCommitment: request.requestCommitment,
      resultBytes: result.body
    })
    const structuredContent = await openVerifiedCellGetResult({
      verifiedResult,
      runtime: internal.runtime,
      readCap: options.readCap
    })
    return Object.freeze({
      structuredContent,
      requestCommitment: b4a.from(request.requestCommitment),
      endpointContext
    })
  }
}

export function createBlindCellGetControl (options) {
  return new BlindCellGetControl(options)
}

export { createBrowserCryptoRuntime }
