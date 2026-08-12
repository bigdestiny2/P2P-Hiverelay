import b4a from 'b4a'
import {
  FAMILY,
  OPERATION
} from '../../blind-protocol/wire-runtime-authority.js'
import { blindServiceDescriptorV1 } from '../../blind-protocol/schemas.js'
import { decodeCanonical } from '../../blind-protocol/codec.js'
import { serviceDescriptorHash } from '../../blind-protocol/hashes.js'
import { asBytes } from '../../blind-client/bytes.js'
import {
  DescriptorTrustStore
} from '../../blind-client/describe.js'
import { BlindDescriptorBootstrapHttpClient as AcceptedBootstrapClient } from '../../blind-client/bootstrap-http.js'
import { BlindDirectHttpClient as AcceptedDirectClient } from '../../blind-client/direct-http.js'
import { fail } from '../../blind-client/errors.js'
import { BlindRelayQualifier as AcceptedRelayQualifier } from '../../blind-client/qualification.js'
import { verifiedEndpointContext } from '../../blind-client/verified-endpoint.js'
import { createBrowserCryptoRuntime } from '../../blind-client/runtime/browser.js'
import { createGetCellRequest } from './cell-get-requests.js'
import {
  openVerifiedCellGetResult,
  verifyCellGetResult
} from './cell-get-results.js'

const MAX_DESCRIPTOR_SEQUENCE = 4095n
const CONTROL_INTERNALS = new WeakMap()
const FORBIDDEN_OPERATION_FIELDS = Object.freeze([
  'familyId',
  'operationId',
  'requested',
  'body',
  'expectedResultBodyBytes',
  'outerClass'
])

function sameBytes (left, right) {
  return b4a.equals(b4a.from(left), b4a.from(right))
}

function boundFetch (options) {
  return options.fetch ||
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : globalThis.fetch)
}

class BoundBootstrapClient extends AcceptedBootstrapClient {
  constructor (options = {}) {
    super({ ...options, fetch: boundFetch(options) })
  }
}

class BoundDirectClient extends AcceptedDirectClient {
  constructor (options = {}) {
    super({ ...options, fetch: boundFetch(options) })
  }
}

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

function decodedDescriptor (internal, verified, expectedHash) {
  if (!internal.descriptorBrands.has(verified)) {
    fail('BAD_CLIENT_INPUT', 'a descriptor from this control is required')
  }
  const snapshot = verified.snapshotBytes()
  const hash = serviceDescriptorHash(snapshot)
  if (!sameBytes(hash, verified.descriptorHash) ||
      (expectedHash != null && !sameBytes(hash, expectedHash))) {
    fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor snapshot does not match its authenticated hash')
  }
  return decodeCanonical(blindServiceDescriptorV1, snapshot, { copyBytes: true })
}

async function fetchDescriptor (internal, candidate, expectedDescriptorHash, history) {
  return internal.bootstrapClient.fetchVerifiedDescriptor({
    canonicalUrl: candidate.canonicalUrl,
    expectedDescriptorHash,
    clientNonce: candidate.clientNonce,
    requestId: candidate.requestId,
    nowEpoch: internal.nowEpoch(),
    history,
    supportedProtocolProfiles: internal.supportedProtocolProfiles,
    supportedTransportProfiles: internal.supportedTransportProfiles,
    timeoutMillis: candidate.timeoutMillis,
    signal: candidate.signal
  })
}

function descriptorStoreKey (continuityRootRelayPublicKey, storeId) {
  return `descriptor:${b4a.toString(continuityRootRelayPublicKey, 'hex')}:${b4a.toString(storeId, 'hex')}`
}

function validatePersistedPrefix (state, chain, continuityRootRelayPublicKey) {
  if (!state || state.quarantined !== false ||
      typeof state.sequence !== 'bigint' ||
      state.sequence < 0n ||
      state.sequence >= BigInt(chain.length)) {
    fail('DESCRIPTOR_CHAIN_INVALID', 'persisted descriptor trust has an invalid sequence')
  }
  const index = Number(state.sequence)
  const entry = chain[index]
  const snapshot = entry.verified.snapshotBytes()
  if (!sameBytes(state.rootRelayPublicKey, continuityRootRelayPublicKey) ||
      !sameBytes(state.storeId, entry.value.storeId) ||
      !sameBytes(state.currentBytes, snapshot) ||
      !sameBytes(state.currentHash, entry.verified.descriptorHash) ||
      !sameBytes(serviceDescriptorHash(state.currentBytes), entry.verified.descriptorHash) ||
      BigInt(state.identitySequence) !== BigInt(entry.value.identitySequence) ||
      !sameBytes(state.relayPublicKey, entry.value.relayPublicKey) ||
      state.durabilityProfileId !== entry.value.durability.profileId ||
      !sameBytes(state.durabilityContinuityHash, entry.value.durabilityContinuityHash) ||
      !Array.isArray(state.history) ||
      state.history.length !== index + 1) {
    fail('DESCRIPTOR_CHAIN_INVALID', 'persisted descriptor trust does not match the authenticated chain')
  }
  for (let historyIndex = 0; historyIndex <= index; historyIndex++) {
    const expected = chain[historyIndex].verified.snapshotBytes()
    if (!sameBytes(state.history[historyIndex], expected) ||
        !sameBytes(serviceDescriptorHash(state.history[historyIndex]),
          chain[historyIndex].verified.descriptorHash)) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'persisted descriptor history does not match the authenticated chain')
    }
  }
  return index
}

async function reconstructTrust (internal, candidate) {
  if (!candidate || typeof candidate !== 'object') {
    fail('BAD_CLIENT_INPUT', 'relay candidate is required')
  }
  const expectedHeadHash = b4a.from(asBytes(
    candidate.expectedDescriptorHash, 'candidate expectedDescriptorHash', 32))
  const continuityRootRelayPublicKey = b4a.from(asBytes(
    candidate.continuityRootRelayPublicKey, 'candidate continuityRootRelayPublicKey', 32))
  const head = await fetchDescriptor(internal, candidate, expectedHeadHash, false)
  internal.descriptorBrands.add(head)
  const headValue = decodedDescriptor(internal, head, expectedHeadHash)
  const headSequence = BigInt(headValue.descriptorSequence)
  if (headSequence > MAX_DESCRIPTOR_SEQUENCE) {
    fail('DESCRIPTOR_HISTORY_LIMIT', 'descriptor head sequence exceeds 4095')
  }
  const reverse = [{ verified: head, value: headValue }]
  const seen = new Set([b4a.toString(head.descriptorHash, 'hex')])
  for (let sequence = headSequence; sequence > 0n; sequence--) {
    const current = reverse[reverse.length - 1].value
    if (current.previousDescriptorHash == null) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'non-genesis descriptor omitted previousDescriptorHash')
    }
    const requestedHash = b4a.from(asBytes(
      current.previousDescriptorHash, 'previousDescriptorHash', 32))
    const requestedHex = b4a.toString(requestedHash, 'hex')
    if (seen.has(requestedHex)) fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor chain repeats a hash')
    const previous = await fetchDescriptor(internal, candidate, requestedHash, true)
    internal.descriptorBrands.add(previous)
    if (!sameBytes(previous.descriptorHash, requestedHash)) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor predecessor does not match the requested hash')
    }
    const previousValue = decodedDescriptor(internal, previous, requestedHash)
    if (BigInt(previousValue.descriptorSequence) !== sequence - 1n) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor sequence is not contiguous')
    }
    if (!sameBytes(previousValue.storeId, headValue.storeId)) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor chain changed its store identity')
    }
    seen.add(requestedHex)
    reverse.push({ verified: previous, value: previousValue })
  }
  const genesis = reverse[reverse.length - 1]
  if (BigInt(genesis.value.descriptorSequence) !== 0n ||
      genesis.value.previousDescriptorHash != null) {
    fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor genesis is not sequence zero with a null predecessor')
  }
  if (!sameBytes(genesis.value.relayPublicKey, continuityRootRelayPublicKey)) {
    fail('UNTRUSTED_RELAY_IDENTITY', 'candidate continuity root does not match descriptor genesis')
  }
  const chain = reverse.reverse()
  const record = await internal.trustBackend.read(descriptorStoreKey(
    continuityRootRelayPublicKey, headValue.storeId))
  let trusted
  let firstMissing = 0
  if (record.value != null) {
    const persistedIndex = validatePersistedPrefix(
      record.value, chain, continuityRootRelayPublicKey)
    const persisted = chain[persistedIndex]
    trusted = await internal.trustStore.accept(persisted.verified, {
      continuityRootRelayPublicKey
    })
    firstMissing = persistedIndex + 1
  }
  for (let index = firstMissing; index < chain.length; index++) {
    const entry = chain[index]
    trusted = await internal.trustStore.accept(entry.verified, {
      ...(index === 0
        ? { pinnedDescriptorHash: entry.verified.descriptorHash }
        : {}),
      continuityRootRelayPublicKey
    })
  }
  return Object.freeze({ head, trusted, expectedHeadHash, continuityRootRelayPublicKey })
}

class BlindCellGetControl {
  constructor (options = {}) {
    if (typeof options.nowEpoch !== 'function') {
      fail('BAD_CLIENT_INPUT', 'nowEpoch provider is required')
    }
    const supportedProtocolProfiles = profilePins(
      options.supportedProtocolProfiles, 'profileHash', 'supportedProtocolProfiles')
    const supportedTransportProfiles = profilePins(
      options.supportedTransportProfiles, 'transportProfileHash', 'supportedTransportProfiles')
    const fetch = boundFetch(options)
    const trustStore = new DescriptorTrustStore(options.trustBackend)
    const bootstrapClient = new BoundBootstrapClient({
      runtime: options.runtime,
      fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    const directClient = new BoundDirectClient({
      runtime: options.runtime,
      fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    const qualifier = new AcceptedRelayQualifier({
      runtime: options.runtime,
      nowEpoch: options.nowEpoch,
      monotonicMillis: options.monotonicMillis,
      supportedProtocolProfiles,
      supportedTransportProfiles,
      trustStore,
      bootstrapClient,
      directClient,
      fetch,
      allowInsecureLoopback: options.allowInsecureLoopback
    })
    CONTROL_INTERNALS.set(this, Object.freeze({
      runtime: options.runtime,
      nowEpoch: options.nowEpoch,
      supportedProtocolProfiles,
      supportedTransportProfiles,
      trustStore,
      trustBackend: trustStore.backend,
      bootstrapClient,
      directClient,
      qualifier,
      descriptorBrands: new WeakSet(),
      endpointBrands: new WeakSet()
    }))
    Object.freeze(this)
  }

  async qualifyCellGetCandidate (candidate, options = {}) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'CELL.GET qualification')
    const reconstructed = await reconstructTrust(internal, candidate)
    const qualified = await internal.qualifier.qualifyCandidate(candidate, {
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
    if (!sameBytes(qualified.descriptorHash, reconstructed.expectedHeadHash) ||
        !sameBytes(qualified.continuityRootRelayPublicKey,
          reconstructed.continuityRootRelayPublicKey)) {
      fail('DESCRIPTOR_CHAIN_INVALID', 'qualified descriptor does not match the reconstructed head')
    }
    const context = verifiedEndpointContext(qualified.endpoint)
    if (!sameBytes(context.descriptorHash, reconstructed.expectedHeadHash) ||
        context.familyId !== FAMILY.CELL || context.operationId !== OPERATION.CELL.GET) {
      fail('BAD_CLIENT_INPUT', 'qualified endpoint is not the authenticated CELL.GET head')
    }
    internal.endpointBrands.add(qualified.endpoint)
    return qualified.endpoint
  }

  async readCell (options) {
    const internal = controlInternals(this)
    rejectOperationSelection(options, 'CELL.GET')
    if (!internal.endpointBrands.has(options.endpoint)) {
      fail('BAD_CLIENT_INPUT', 'a CELL.GET endpoint from this control is required')
    }
    const endpointContext = verifiedEndpointContext(options.endpoint)
    if (endpointContext.familyId !== FAMILY.CELL ||
        endpointContext.operationId !== OPERATION.CELL.GET) {
      fail('BAD_CLIENT_INPUT', 'qualified endpoint is not CELL.GET')
    }
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
      requestCommitment: b4a.from(request.requestCommitment)
    })
  }
}

export function createBlindCellGetControl (options) {
  return new BlindCellGetControl(options)
}

export { createBrowserCryptoRuntime }
