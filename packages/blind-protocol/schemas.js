import b4a from 'b4a'
import {
  arrayOf,
  boundedBytes,
  canonicalAsciiBytes,
  canonicalHttpsUrlBytes,
  canonicalUtf8Bytes,
  constant,
  constantBytes,
  encodeCanonical,
  exactBytesByClass,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u16be,
  u32be,
  u64be,
  validateCanonicalUrl
} from './codec.js'
import { protocolError } from './errors.js'
import { blake2b256, cellStorageSlot, inboxPhysicalTopic } from './hashes.js'
import { relayResultBindingV1 } from './result-binding.js'
import {
  admissionCostRule as lookupAdmissionCostRule,
  ADMISSION_CONFORMANCE_CLASS,
  CELL_RECEIPT_RESULT,
  CELL_SIZE_CLASS,
  CORE_ACK_RESULT,
  CORE_SESSION_CLASS,
  DISPATCH_LIMITS,
  DOMAIN_RECIPE,
  DOMAIN_PURPOSE,
  ERROR_PROFILE_ID,
  ERROR_RETRY_AFTER_MODE,
  ENDPOINT_LIMITS,
  FAMILY,
  FAMILY_ROUTES,
  FRAME_KIND,
  FORWARD_CLOSE_KIND,
  FORWARD_CIRCUIT_CLASS,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  INBOX_APPEND_AUTH_MODE,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  INBOX_RECEIPT_RESULT,
  PUBLIC_PROFILE_LIMITS,
  STORE_LIFECYCLE_STATE,
  STREAM_TRANSITION,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  domainRegistryEntry as lookupDomainRegistryEntry,
  errorProfileEntry as lookupErrorProfileEntry,
  operationProfile as lookupOperationProfile
} from './wire-runtime-authority.js'
import { SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY } from './schema-catalog-runtime-authority.js'

const KiB = 1024
const MiB = 1024 * KiB
const MAX_U64 = (1n << 64n) - 1n

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function bigint (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function isAllZero (value) {
  for (let i = 0; i < value.byteLength; i++) {
    if (value[i] !== 0) return false
  }
  return true
}

function validateEpochWindow (value) {
  if (value.issuedEpoch >= value.expiresEpoch || value.expiresEpoch - value.issuedEpoch > 4) {
    fail('route epoch window must satisfy issuedEpoch < expiresEpoch <= issuedEpoch + 4')
  }
}

function validateForwardTuple (value) {
  const tuple = FORWARD_CIRCUIT_CLASS[value.circuitClass]
  if (!tuple) fail('circuitClass is outside 1..3')
  if (value.grantedInitialWindow !== tuple.grantedInitialWindow ||
      bigint(value.maxCircuitBytes, 'maxCircuitBytes') !== BigInt(tuple.maxCircuitBytes) ||
      value.idleMillis !== tuple.idleMillis || value.lifetimeMillis !== tuple.lifetimeMillis) {
    fail('forward circuit limits do not match the frozen class tuple')
  }
  if (value.maxDataBytes !== STREAM_WIRE_CLASS[value.grantedWireClass == null
    ? value.requestedWireClass
    : value.grantedWireClass]) {
    fail('maxDataBytes does not match the selected wire class')
  }
}

function validateCoreTuple (value) {
  const tuple = CORE_SESSION_CLASS[value.sessionClass]
  if (!tuple) fail('sessionClass is outside 1..3')
  if (bigint(value.maxSessionBytes, 'maxSessionBytes') !== BigInt(tuple.maxSessionBytes) ||
      value.idleMillis !== tuple.idleMillis || value.lifetimeMillis !== tuple.lifetimeMillis) {
    fail('core session limits do not match the frozen class tuple')
  }
}

const bytes16 = fixedBytes(16)
const bytes32 = fixedBytes(32)
const bytes64 = fixedBytes(64)
const bytes96 = fixedBytes(96)
const version1 = constant(u8, 1, 'version')
const profileId = ranged(u16be, 1, 0xffff, 'profileId')
const schemeId = ranged(u16be, 1, 0xffff, 'schemeId')
const endpointId = ranged(u8, 1, 0xff, 'endpointId')
const transportSupportBit = ranged(u16be, 1, 0x3f, 'transportSupportBit')
const wireClass = ranged(u8, 1, 3, 'wireClass')
const circuitClass = ranged(u8, 1, 3, 'circuitClass')
const sessionClass = ranged(u8, 1, 3, 'sessionClass')
const protocolId = ranged(u16be, 1, 5, 'protocolId')
const transportId = ranged(u8, 1, 9, 'transportId')
const cellSizeClass = ranged(u8, 1, 5, 'sizeClass')
const inboxFrameClass = ranged(u8, 1, 3, 'frameClass')
const leaseClass = ranged(u8, 1, 4, 'leaseClass')
const optionalLeaseClass = ranged(u8, 0, 4, 'leaseClass')
const cellBlob = exactBytesByClass('sizeClass', CELL_SIZE_CLASS, 'cellBlob')
const inboxFrame = exactBytesByClass('frameClass', INBOX_FRAME_CLASS, 'inbox frame')
const profileName = canonicalAsciiBytes(1, 64, 'profileName')
const endpointUrl = canonicalUtf8Bytes(1, 512, 'endpoint URL')
const buildManifestUrl = canonicalHttpsUrlBytes('buildManifestUrl')
const buildArtifactUrl = canonicalHttpsUrlBytes('buildArtifactUrl')
const releaseEvidenceBundleUrl = canonicalHttpsUrlBytes('releaseEvidenceBundleUrl')
const runtimeBoundaryEvidenceUrl = canonicalHttpsUrlBytes('runtimeBoundaryEvidenceUrl')
const externalJournalTopologyUrl = canonicalHttpsUrlBytes('externalJournalTopologyUrl')
const restoreEvidenceFeedUrl = canonicalHttpsUrlBytes('restoreEvidenceFeedUrl')
const cellProtocol = constantBytes(b4a.from('hiverelay-blind-cell-v1', 'ascii'), 'cell receipt protocol')

function bytesKey (value) {
  return b4a.toString(value, 'hex')
}

function assertDistinctBytes (values, name) {
  const seen = new Set()
  for (const value of values) {
    const key = bytesKey(value)
    if (seen.has(key)) fail(`${name} contains a duplicate`)
    seen.add(key)
  }
}

function compareBytes (a, b) {
  const length = Math.min(a.byteLength, b.byteLength)
  for (let index = 0; index < length; index++) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1
  }
  return a.byteLength === b.byteLength ? 0 : a.byteLength < b.byteLength ? -1 : 1
}

function compareScalar (a, b) {
  return a === b ? 0 : a < b ? -1 : 1
}

function assertStrictlySorted (values, compare, name) {
  for (let index = 1; index < values.length; index++) {
    if (compare(values[index - 1], values[index]) >= 0) fail(`${name} must be strictly sorted and duplicate-free`)
  }
}

function assertNonzeroBytes (value, name) {
  if (isAllZero(value)) fail(`${name} must be nonzero`)
}

function cappedEncoding (encoding, maximum, name) {
  const capped = {
    preencode (state, value) {
      const start = state.end
      encoding.preencode(state, value)
      if (state.end - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
    },
    encode (state, value) {
      encoding.encode(state, value)
    },
    decode (state) {
      const start = state.start
      const value = encoding.decode(state)
      if (state.start - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
      return value
    }
  }
  if (Array.isArray(encoding.schemaFields)) {
    Object.defineProperties(capped, {
      schemaName: {
        value: encoding.schemaName || name
      },
      schemaFields: {
        value: encoding.schemaFields
      }
    })
  }
  return capped
}

export const admissionCostRuleV1 = struct([
  ['costClassRuleId', ranged(u16be, 1, 11, 'costClassRuleId')],
  ['ruleKind', ranged(u8, 1, 11, 'ruleKind')]
], {
  name: 'AdmissionCostRuleV1',
  validate (value) {
    const expected = lookupAdmissionCostRule(value.costClassRuleId)
    if (!expected || expected.ruleKind !== value.ruleKind) fail('admission cost rule is not in the frozen registry')
  }
})

export const domainRegistryEntryV1 = struct([
  ['domainId', ranged(u16be, 1, 0xffff, 'domainId')],
  ['purpose', ranged(u8, DOMAIN_PURPOSE.REQUEST_COMMITMENT, DOMAIN_PURPOSE.AUXILIARY_SIGNATURE, 'domain purpose')],
  ['recipeId', ranged(u8, DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE,
    DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD, 'domain recipe')],
  ['exactAsciiBytes', canonicalAsciiBytes(1, 96, 'exactAsciiBytes')]
], {
  name: 'DomainRegistryEntryV1',
  validate (value) {
    const expected = lookupDomainRegistryEntry(value.domainId)
    if (!expected || expected.purpose !== value.purpose || expected.recipeId !== value.recipeId ||
        !b4a.equals(b4a.from(expected.exactAsciiBytes, 'ascii'), value.exactAsciiBytes)) {
      fail('domain entry is not in the frozen registry')
    }
  }
})

export const errorProfileEntryV1 = struct([
  ['errorProfileId', constant(u8, ERROR_PROFILE_ID.CANONICAL_V1, 'errorProfileId')],
  ['code', ranged(u8, 1, 20, 'error code')],
  ['directCorrelatedStatus', constant(u16be, 200, 'directCorrelatedStatus')],
  ['protectedInnerStatus', constant(u16be, 200, 'protectedInnerStatus')],
  ['retryable', ranged(u8, 0, 1, 'retryable')],
  ['retryAfterMode', ranged(u8, ERROR_RETRY_AFTER_MODE.MUST_BE_ABSENT,
    ERROR_RETRY_AFTER_MODE.MUST_BE_PRESENT, 'retryAfterMode')]
], {
  name: 'ErrorProfileEntryV1',
  validate (value) {
    const expected = lookupErrorProfileEntry(value.errorProfileId, value.code)
    if (!expected || expected.directCorrelatedStatus !== value.directCorrelatedStatus ||
        expected.protectedInnerStatus !== value.protectedInnerStatus ||
        expected.retryable !== value.retryable || expected.retryAfterMode !== value.retryAfterMode) {
      fail('error profile entry is not in the frozen registry')
    }
  }
})

export const admissionV1 = struct([
  ['profileId', profileId],
  ['schemeId', schemeId],
  ['parameterHash', bytes32],
  ['token', boundedBytes(1, 4096, 'admission token')]
], { name: 'AdmissionV1' })

export const blindReceiptV1 = struct([
  ['version', version1],
  ['protocol', cellProtocol],
  ['relayBinding', relayResultBindingV1],
  ['slotCommitment', bytes32],
  ['cellBlobHash', bytes32],
  ['allocationCommitment', bytes32],
  ['requestCommitment', bytes32],
  ['sizeClass', cellSizeClass],
  ['allocationEpoch', u32be],
  ['leaseClass', optionalLeaseClass],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['receiptEpoch', u32be],
  ['requestNonce', bytes32],
  ['result', ranged(u8, CELL_RECEIPT_RESULT.STORED, CELL_RECEIPT_RESULT.DROPPED, 'cell receipt result')],
  ['signature', bytes64]
], {
  name: 'BlindReceiptV1',
  validate (value) {
    if (value.result === CELL_RECEIPT_RESULT.DROPPED) {
      if (value.leaseClass !== 0) fail('dropped cell receipt must use lease NONE')
    } else if (value.leaseClass === 0) fail('stored, served, or renewed cell receipt requires a lease')
  }
})

export const putCellV1 = /* @__PURE__ */ struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['allocationEpoch', u32be],
  ['sizeClass', cellSizeClass],
  ['leaseClass', leaseClass],
  ['clientNonce', bytes32],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['dropPublicKey', bytes32],
  ['declaredBlobHash', bytes32],
  ['createSignature', bytes64],
  ['admission', admissionV1],
  ['cellBlob', cellBlob]
], {
  name: 'PutCellV1',
  validate (value) {
    if (!b4a.equals(cellStorageSlot(value), value.storageSlot)) fail('storageSlot is not self-certifying')
    if (!b4a.equals(blake2b256(value.cellBlob), value.declaredBlobHash)) {
      fail('declaredBlobHash does not match cellBlob')
    }
  }
})

export const renewCellV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['expectedRevision', u64be],
  ['expectedLeaseEpoch', u32be],
  ['leaseClass', leaseClass],
  ['clientNonce', bytes32],
  ['admission', admissionV1],
  ['signature', bytes64]
], { name: 'RenewCellV1' })

export const dropCellV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['expectedRevision', u64be],
  ['expectedLeaseEpoch', u32be],
  ['clientNonce', bytes32],
  ['signature', bytes64]
], { name: 'DropCellV1' })

export const proveCellV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['clientNonce', bytes32],
  ['admission', optional(admissionV1, 'admission')]
], { name: 'ProveCellV1' })

export const getCellV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['clientNonce', bytes32],
  ['admission', optional(admissionV1, 'admission')]
], { name: 'GetCellV1' })

export const getCellResultV1 = struct([
  ['version', version1],
  ['sizeClass', cellSizeClass],
  ['cellBlob', cellBlob]
], { name: 'GetCellResultV1' })

export const proveCellResultV1 = struct([
  ['version', version1],
  ['receipt', blindReceiptV1],
  ['sizeClass', cellSizeClass],
  ['cellBlob', cellBlob]
], {
  name: 'ProveCellResultV1',
  validate (value) {
    if (value.receipt.result !== CELL_RECEIPT_RESULT.SERVED) fail('proof receipt result must be SERVED')
    if (value.receipt.sizeClass !== value.sizeClass) fail('proof sizeClass does not match receipt')
    if (!b4a.equals(blake2b256(value.cellBlob), value.receipt.cellBlobHash)) {
      fail('proof cellBlob does not match receipt hash')
    }
  }
})

const batchGetFoundV1 = struct([
  ['sizeClass', cellSizeClass],
  ['cellBlob', cellBlob]
], { name: 'BatchGetEntryV1.found' })

export const batchGetEntryV1 = {
  preencode (state, value) {
    if (!value || typeof value !== 'object') fail('BatchGetEntryV1 must be an object')
    u8.preencode(state, value.status)
    if (value.status === 0) return
    if (value.status !== 1) fail('BatchGetEntryV1 status must be 0 or 1')
    batchGetFoundV1.preencode(state, value)
  },
  encode (state, value) {
    if (!value || typeof value !== 'object') fail('BatchGetEntryV1 must be an object')
    u8.encode(state, value.status)
    if (value.status === 0) return
    if (value.status !== 1) fail('BatchGetEntryV1 status must be 0 or 1')
    batchGetFoundV1.encode(state, value)
  },
  decode (state) {
    const status = u8.decode(state)
    if (status === 0) return { status }
    if (status !== 1) fail('BatchGetEntryV1 status must be 0 or 1')
    return { status, ...batchGetFoundV1.decode(state) }
  }
}

const batchGetSlotsV1 = arrayOf(bytes32, 1, 64, 'batch slots')
const batchGetEntriesV1 = arrayOf(batchGetEntryV1, 1, 64, 'batch entries')

export function batchGetEntriesCommitment (entries) {
  return blake2b256(encodeCanonical(batchGetEntriesV1, entries))
}

export const batchGetV1 = struct([
  ['version', version1],
  ['clientNonce', bytes32],
  ['slots', batchGetSlotsV1],
  ['admission', optional(admissionV1, 'admission')]
], {
  name: 'BatchGetV1',
  validate (value) {
    assertDistinctBytes(value.slots, 'batch slots')
  }
})

export const batchGetResultV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['entries', batchGetEntriesV1],
  ['entriesCommitment', bytes32],
  ['signature', bytes64]
], {
  name: 'BatchGetResultV1',
  validate (value) {
    const entriesBytes = encodeCanonical(batchGetEntriesV1, value.entries)
    const expected = blake2b256(entriesBytes)
    if (!b4a.equals(expected, value.entriesCommitment)) fail('batch entriesCommitment does not match entries')
    if (193 + entriesBytes.byteLength > 4 * MiB) fail('batch result exceeds its operation cap')
  }
})

export const inboxCreateV1 = struct([
  ['version', version1],
  ['allocationEpoch', u32be],
  ['physicalTopic', bytes32],
  ['frameClassBits', u8],
  ['appendAuthMode', ranged(u8, 0, 1, 'appendAuthMode')],
  ['createPublicKey', bytes32],
  ['appendPublicKey', optional(bytes32, 'appendPublicKey')],
  ['renewPublicKey', bytes32],
  ['closePublicKey', bytes32],
  ['retentionClass', leaseClass],
  ['leaseClass', leaseClass],
  ['clientNonce', bytes32],
  ['createSignature', bytes64],
  ['admission', admissionV1]
], {
  name: 'InboxCreateV1',
  validate (value) {
    if (!b4a.equals(inboxPhysicalTopic(value), value.physicalTopic)) fail('physicalTopic is not self-certifying')
    if (value.frameClassBits === 0 || (value.frameClassBits & ~0x07) !== 0) {
      fail('frameClassBits must contain only advertised inbox classes')
    }
    const signatureRequired = value.appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
    if (signatureRequired !== (value.appendPublicKey != null)) {
      fail('appendPublicKey presence does not match appendAuthMode')
    }
  }
})

export const inboxManageV1 = struct([
  ['version', version1],
  ['operation', ranged(u8, 1, 2, 'inbox management operation')],
  ['physicalTopic', bytes32],
  ['expectedRevision', u64be],
  ['expectedLeaseEpoch', u32be],
  ['leaseClass', optionalLeaseClass],
  ['clientNonce', bytes32],
  ['signature', bytes64],
  ['admission', optional(admissionV1, 'admission')]
], {
  name: 'InboxManageV1',
  validate (value) {
    if (value.operation === INBOX_MANAGE_OPERATION.RENEW) {
      if (value.leaseClass === 0 || value.admission == null) fail('inbox renew requires lease and admission')
    } else if (value.leaseClass !== 0 || value.admission != null) {
      fail('inbox close requires lease NONE and no admission')
    }
  }
})

export const inboxAppendV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['frameClass', inboxFrameClass],
  ['frameHash', bytes32],
  ['clientNonce', bytes32],
  ['appendSignature', optional(bytes64, 'appendSignature')],
  ['admission', admissionV1],
  ['frame', inboxFrame]
], {
  name: 'InboxAppendV1',
  validate (value) {
    if (!b4a.equals(blake2b256(value.frame), value.frameHash)) fail('frameHash does not match frame')
  }
})

export const inboxReadV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['cursor', boundedBytes(0, 128, 'inbox cursor')],
  ['limit', ranged(u16be, 1, 64, 'inbox read limit')],
  ['clientNonce', bytes32],
  ['admission', optional(admissionV1, 'admission')]
], { name: 'InboxReadV1' })

export const inboxWatchV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['afterRevision', u64be],
  ['limit', ranged(u16be, 1, 64, 'inbox watch limit')],
  ['maxWaitMillis', ranged(u16be, 1, 30000, 'maxWaitMillis')],
  ['clientNonce', bytes32],
  ['admission', admissionV1]
], { name: 'InboxWatchV1' })

export const inboxReceiptV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['topicCommitment', bytes32],
  ['stateRevision', u64be],
  ['leaseClass', optionalLeaseClass],
  ['leaseEpoch', u32be],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['result', ranged(u8, 1, 3, 'inbox receipt result')],
  ['signature', bytes64]
], {
  name: 'InboxReceiptV1',
  validate (value) {
    if (value.result === INBOX_RECEIPT_RESULT.CLOSED) {
      if (value.leaseClass !== 0) fail('closed inbox receipt must use lease NONE')
    } else if (value.leaseClass === 0) fail('created or renewed inbox receipt requires a lease')
  }
})

export const inboxAppendAckV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['topicCommitment', bytes32],
  ['frameHash', bytes32],
  ['appendRevision', u64be],
  ['storedAtEpoch', u32be],
  ['expiresAtEpoch', u32be],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['result', constant(u8, INBOX_APPEND_RESULT.STORED, 'result')],
  ['signature', bytes64]
], {
  name: 'InboxAppendAckV1',
  validate (value) {
    if (value.expiresAtEpoch <= value.storedAtEpoch) fail('expiresAtEpoch must be after storedAtEpoch')
  }
})

export const inboxReadEntryV1 = struct([
  ['appendRevision', u64be],
  ['frameHash', bytes32],
  ['frameClass', inboxFrameClass],
  ['frame', inboxFrame]
], {
  name: 'InboxReadResultV1.entry',
  validate (value) {
    if (!b4a.equals(blake2b256(value.frame), value.frameHash)) fail('entry frameHash does not match frame')
  }
})

const inboxReadEntriesV1 = arrayOf(inboxReadEntryV1, 0, 64, 'inbox read entries')
const inboxNextCursorV1 = optional(boundedBytes(0, 128, 'nextCursor'), 'nextCursor')

export function inboxReadEntriesCommitment (entries) {
  return blake2b256(encodeCanonical(inboxReadEntriesV1, entries))
}

export const inboxReadResultV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['snapshotRevision', u64be],
  ['entries', inboxReadEntriesV1],
  ['entriesCommitment', bytes32],
  ['nextCursor', inboxNextCursorV1],
  ['signature', bytes64]
], {
  name: 'InboxReadResultV1',
  validate (value) {
    let previous = -1n
    for (const entry of value.entries) {
      const revision = bigint(entry.appendRevision, 'appendRevision')
      if (revision <= previous) fail('inbox entries must have strictly increasing appendRevision')
      if (revision > bigint(value.snapshotRevision, 'snapshotRevision')) {
        fail('inbox entry revision exceeds snapshotRevision')
      }
      previous = revision
    }
    const entriesBytes = encodeCanonical(inboxReadEntriesV1, value.entries)
    const expected = blake2b256(entriesBytes)
    if (!b4a.equals(expected, value.entriesCommitment)) fail('inbox entriesCommitment does not match entries')
    const resultBytes = 105 + entriesBytes.byteLength + 32 +
      encodeCanonical(inboxNextCursorV1, value.nextCursor).byteLength + 64
    if (resultBytes > 4 * MiB) fail('inbox read result exceeds its operation cap')
  }
})

export const blindErrorV1 = struct([
  ['version', version1],
  ['code', ranged(u8, 1, 20, 'error code')],
  ['retryable', ranged(u8, 0, 1, 'retryable')],
  ['retryAfterEpoch', optional(u32be, 'retryAfterEpoch')]
], {
  name: 'BlindErrorV1',
  validate (value) {
    const profile = lookupErrorProfileEntry(ERROR_PROFILE_ID.CANONICAL_V1, value.code)
    const retryAfterPresent = value.retryAfterEpoch != null
    if (!profile || profile.retryable !== value.retryable ||
        retryAfterPresent !== (profile.retryAfterMode === ERROR_RETRY_AFTER_MODE.MUST_BE_PRESENT)) {
      fail('blind error body does not match error profile 1')
    }
  }
})

export const blindOhttpTransportErrorV1 = struct([
  ['version', version1],
  ['code', ranged(u8, 1, 3, 'OHTTP transport error code')]
], { name: 'BlindOhttpTransportErrorV1' })

export const blindDescribeGetV1 = struct([
  ['version', version1],
  ['descriptorHash', optional(bytes32, 'descriptorHash')],
  ['clientNonce', bytes32]
], { name: 'BlindDescribeGetV1' })

export const blindAdmissionParametersRequestV1 = struct([
  ['version', version1],
  ['profileId', profileId],
  ['schemeId', schemeId],
  ['clientNonce', bytes32]
], { name: 'BlindAdmissionParametersRequestV1' })

export const operationProfileV1 = struct([
  ['familyId', ranged(u8, 1, 5, 'familyId')],
  ['operationId', ranged(u8, 1, 255, 'operationId')],
  ['requestSchemaId', ranged(u16be, 1, 0xffff, 'requestSchemaId')],
  ['resultSchemaId', u16be],
  ['allowedRequestKindBits', ranged(u8, 1, 0x0f, 'allowedRequestKindBits')],
  ['allowedResultKindBits', ranged(u8, 0, 0x0f, 'allowedResultKindBits')],
  ['streamTransition', ranged(u8, 0, 3, 'streamTransition')],
  ['maxRequestBodyBytes', ranged(u32be, 1, 4 * MiB, 'maxRequestBodyBytes')],
  ['maxResultBodyBytes', ranged(u32be, 1, 4 * MiB, 'maxResultBodyBytes')],
  ['admissionMode', ranged(u8, 0, 2, 'admissionMode')],
  ['costClassRuleId', u16be],
  ['requestCommitmentDomainId', u16be],
  ['resultSignatureDomainId', u16be],
  ['errorProfileId', constant(u8, 1, 'errorProfileId')],
  ['transportSupportBits', ranged(u16be, 1, 0x3f, 'transportSupportBits')]
], {
  name: 'OperationProfileV1',
  validate (value) {
    const requestDomain = value.requestCommitmentDomainId === 0
      ? null
      : lookupDomainRegistryEntry(value.requestCommitmentDomainId)
    const resultDomain = value.resultSignatureDomainId === 0
      ? null
      : lookupDomainRegistryEntry(value.resultSignatureDomainId)
    if (value.requestCommitmentDomainId !== 0 &&
        (!requestDomain || requestDomain.purpose !== DOMAIN_PURPOSE.REQUEST_COMMITMENT ||
         requestDomain.recipeId !== DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE)) {
      fail('requestCommitmentDomainId is not a registered request domain')
    }
    if (value.resultSignatureDomainId !== 0 &&
        (!resultDomain || resultDomain.purpose !== DOMAIN_PURPOSE.RESULT_SIGNATURE ||
         resultDomain.recipeId !== DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD)) {
      fail('resultSignatureDomainId is not a registered result-signature domain')
    }
    if ((value.admissionMode === 0) !== (value.costClassRuleId === 0)) {
      fail('costClassRuleId zero state does not match admissionMode')
    }
    if (value.costClassRuleId !== 0 && !lookupAdmissionCostRule(value.costClassRuleId)) {
      fail('costClassRuleId is not in the frozen registry')
    }
    if (value.admissionMode === 2 && value.requestCommitmentDomainId === 0) {
      fail('required admission needs a request commitment domain')
    }
    if (value.resultSchemaId === 0 && value.streamTransition !== 3) {
      fail('only forward-active operations may omit resultSchemaId')
    }
    const requestKind = 1 << (FRAME_KIND.REQUEST - 1)
    const unaryResultKinds = (1 << (FRAME_KIND.RESPONSE - 1)) | (1 << (FRAME_KIND.ERROR - 1))
    const streamKind = 1 << (FRAME_KIND.STREAM - 1)
    const errorKind = 1 << (FRAME_KIND.ERROR - 1)
    if (value.streamTransition === STREAM_TRANSITION.FORWARD_ACTIVE) {
      if (value.familyId !== FAMILY.FORWARD || value.resultSchemaId !== 0 ||
          value.allowedRequestKindBits !== streamKind ||
          (value.allowedResultKindBits !== streamKind && value.allowedResultKindBits !== (streamKind | errorKind)) ||
          value.admissionMode !== 0 || value.costClassRuleId !== 0 ||
          value.requestCommitmentDomainId !== 0 || value.resultSignatureDomainId !== 0) {
        fail('forward-active operation metadata is inconsistent')
      }
    } else if (value.allowedRequestKindBits !== requestKind || value.allowedResultKindBits !== unaryResultKinds ||
        value.resultSchemaId === 0) {
      fail('unary/open operation metadata kind bits are inconsistent')
    }
    const nativeOnly = TRANSPORT_SUPPORT.DIRECT_NATIVE | TRANSPORT_SUPPORT.TOR_NATIVE
    const forwardNative = nativeOnly | TRANSPORT_SUPPORT.MASQUE_NATIVE
    if ((value.streamTransition === STREAM_TRANSITION.CORE_CHILD &&
         (value.familyId !== FAMILY.CORE || value.transportSupportBits !== nativeOnly)) ||
        ((value.streamTransition === STREAM_TRANSITION.FORWARD_OPEN ||
          value.streamTransition === STREAM_TRANSITION.FORWARD_ACTIVE) &&
         (value.familyId !== FAMILY.FORWARD || value.transportSupportBits !== forwardNative))) {
      fail('stream transition transport support is inconsistent')
    }
    const expected = lookupOperationProfile(value.familyId, value.operationId)
    if (!expected || Object.keys(expected).some(field => value[field] !== expected[field])) {
      fail('operation profile is not in the frozen registry')
    }
  }
})

export const protocolProfileArtifactV1 = struct([
  ['version', version1],
  ['protocolId', protocolId],
  ['major', u16be],
  ['minor', u16be],
  ['featureBits', u64be],
  ['wireSchemaSetHash', bytes32],
  ['dependencyManifestHash', bytes32],
  ['interoperabilityVectorSetHash', bytes32]
], { name: 'ProtocolProfileArtifactV1' })

export const transportProfileArtifactV1 = struct([
  ['version', version1],
  ['transportId', transportId],
  ['profileName', profileName],
  ['major', u16be],
  ['minor', u16be],
  ['exporterId', ranged(u8, 0, 1, 'exporterId')],
  ['controlChannelIdType', ranged(u8, 0, 1, 'controlChannelIdType')],
  ['handshakeProfileHash', bytes32],
  ['dependencyManifestHash', bytes32],
  ['interoperabilityVectorSetHash', bytes32]
], { name: 'TransportProfileArtifactV1' })

export const protocolProfileV1 = struct([
  ['protocolId', protocolId],
  ['major', u16be],
  ['minor', u16be],
  ['featureBits', u64be],
  ['profileHash', bytes32]
], { name: 'ProtocolProfileV1' })

export const transportEndpointV1 = struct([
  ['endpointId', endpointId],
  ['transportId', transportId],
  ['transportProfileHash', bytes32],
  ['roleBits', u16be],
  ['privacyProfileBits', u16be],
  ['canonicalUrl', endpointUrl],
  ['endpointKey', optional(bytes32, 'endpointKey')],
  ['envelopeClassBits', u16be],
  ['wireClassBits', u8],
  ['maxStreams', u16be],
  ['auxiliaryUrl', optional(endpointUrl, 'auxiliaryUrl')],
  ['auxiliaryHash', optional(bytes32, 'auxiliaryHash')]
], {
  name: 'TransportEndpointV1',
  validate (value) {
    if ((value.roleBits & ~ENDPOINT_LIMITS.ROLE_BITS_MASK) !== 0) fail('roleBits contains a reserved bit')
    if ((value.privacyProfileBits & ~ENDPOINT_LIMITS.PRIVACY_PROFILE_BITS_MASK) !== 0) {
      fail('privacyProfileBits contains a reserved bit')
    }
    if ((value.envelopeClassBits & ~ENDPOINT_LIMITS.ENVELOPE_CLASS_BITS_MASK) !== 0) {
      fail('envelopeClassBits contains a reserved bit')
    }
    if ((value.wireClassBits & ~ENDPOINT_LIMITS.WIRE_CLASS_BITS_MASK) !== 0) {
      fail('wireClassBits contains a reserved bit')
    }
    if ((value.wireClassBits === 0) !== (value.maxStreams === 0)) {
      fail('wireClassBits and maxStreams must both describe unary or streaming transport')
    }
    const onion = value.transportId === TRANSPORT_ID.TOR_V3_ONION
    validateCanonicalUrl(value.canonicalUrl, { name: 'canonicalUrl', requireOnion: onion })
    const listenerUrl = new URL(b4a.toString(value.canonicalUrl, 'utf8'))
    if (listenerUrl.pathname !== FAMILY_ROUTES[FAMILY.DESCRIBE]) {
      fail('canonicalUrl must use the generic listener authority anchor /api/blind/v1/describe')
    }
    if ((value.auxiliaryUrl == null) !== (value.auxiliaryHash == null)) {
      fail('auxiliaryUrl and auxiliaryHash must be present together')
    }
    if (onion && value.auxiliaryUrl != null) fail('Tor onion endpoints must not advertise an auxiliary URL')
    if (value.auxiliaryUrl != null) validateCanonicalUrl(value.auxiliaryUrl, { name: 'auxiliaryUrl' })
  }
})

export const durabilityProfileV1 = struct([
  ['profileId', ranged(u8, 1, 2, 'profileId')],
  ['storeFormatMajor', u16be],
  ['storeFormatMinor', u16be],
  ['storeFormatHash', bytes32],
  ['externalJournalId', bytes32],
  ['externalWitnessPublicKey', bytes32],
  ['externalJournalReplicationClass', ranged(u8, 0, 1, 'externalJournalReplicationClass')],
  ['externalJournalFailureGroupId', bytes32],
  ['externalCheckpointAgeBand', ranged(u8, 0, 7, 'externalCheckpointAgeBand')],
  ['externalJournalTopologyUrl', optional(externalJournalTopologyUrl, 'externalJournalTopologyUrl')],
  ['externalJournalTopologyHash', bytes32],
  ['restoreEvidenceFeedUrl', optional(restoreEvidenceFeedUrl, 'restoreEvidenceFeedUrl')],
  ['restoreEvidenceFeedId', bytes32],
  ['restoreEvidenceCheckpointSequence', u64be],
  ['restoreEvidenceCheckpointHash', bytes32],
  ['acknowledgedRpoBand', ranged(u8, 0, 3, 'acknowledgedRpoBand')],
  ['targetRtoBand', ranged(u8, 0, 3, 'targetRtoBand')],
  ['redundancyClass', ranged(u8, 0, 2, 'redundancyClass')],
  ['restoreDrillAgeBand', ranged(u8, 0, 7, 'restoreDrillAgeBand')]
], {
  name: 'DurabilityProfileV1',
  validate (value) {
    const externalFields = [
      value.externalJournalId,
      value.externalWitnessPublicKey,
      value.externalJournalFailureGroupId,
      value.externalJournalTopologyHash
    ]
    const restoreSequence = bigint(value.restoreEvidenceCheckpointSequence, 'restoreEvidenceCheckpointSequence')
    const restoreFeedZero = isAllZero(value.restoreEvidenceFeedId)
    const restoreHashZero = isAllZero(value.restoreEvidenceCheckpointHash)
    if (value.profileId === 1) {
      if (externalFields.some(value => !isAllZero(value)) || value.externalJournalReplicationClass !== 0 ||
          value.externalCheckpointAgeBand !== 0 || value.externalJournalTopologyUrl != null ||
          value.restoreEvidenceFeedUrl != null || !restoreFeedZero || restoreSequence !== 0n || !restoreHashZero ||
          value.acknowledgedRpoBand !== 0 || value.targetRtoBand !== 0 || value.redundancyClass !== 0 ||
          value.restoreDrillAgeBand !== 0) {
        fail('durability profile 1 requires the exact zero/absent external tuple')
      }
      return
    }
    if (externalFields.some(isAllZero) || value.externalJournalReplicationClass !== 1 ||
        value.externalJournalTopologyUrl == null) {
      fail('durability profile 2 requires its nonzero external journal topology tuple')
    }
    if ((value.restoreEvidenceFeedUrl == null) !== restoreFeedZero ||
        (restoreSequence === 0n) !== restoreHashZero ||
        (restoreFeedZero && (restoreSequence !== 0n || !restoreHashZero))) {
      fail('restore evidence feed URL, ID, sequence, and hash zero state is inconsistent')
    }
    const bodyRecoveryClaim = value.acknowledgedRpoBand !== 0 || value.targetRtoBand !== 0 ||
      value.redundancyClass !== 0 || value.restoreDrillAgeBand !== 0
    if (bodyRecoveryClaim && restoreFeedZero) fail('body recovery claims require a restore evidence feed')
  }
})

export const buildProfileV1 = struct([
  ['specHash', bytes32],
  ['abiHash', bytes32],
  ['vectorSetHash', bytes32],
  ['evidenceFormatHash', bytes32],
  ['evidenceVectorSetHash', bytes32],
  ['storeFormatHash', bytes32],
  ['storeVectorSetHash', bytes32],
  ['privateIpcFormatHash', bytes32],
  ['privateIpcVectorSetHash', bytes32],
  ['buildArtifactHash', bytes32],
  ['buildArtifactUrl', buildArtifactUrl],
  ['buildManifestUrl', buildManifestUrl],
  ['buildManifestHash', bytes32],
  ['releaseEvidenceBundleUrl', releaseEvidenceBundleUrl],
  ['releaseEvidenceBundleHash', bytes32],
  ['releaseSupportHorizonHash', bytes32],
  ['runtimeBoundaryEvidenceUrl', runtimeBoundaryEvidenceUrl],
  ['runtimeBoundaryEvidenceHash', bytes32]
], { name: 'BuildProfileV1' })

export const blindTransportRouteV1 = struct([
  ['version', version1],
  ['routeKind', ranged(u8, 1, 6, 'routeKind')],
  ['routeId', bytes16],
  ['previousRelayKey', bytes32],
  ['previousEndpointId', endpointId],
  ['nextRelayKey', bytes32],
  ['nextDescriptorSequence', u64be],
  ['nextDescriptorHash', bytes32],
  ['nextEndpointId', endpointId],
  ['envelopeClassBits', u16be],
  ['wireClassBits', u8],
  ['maxCanonicalDispatchBytes', u32be],
  ['maxEncapsulatedRequestBytes', u32be],
  ['maxOpenBytes', u32be],
  ['maxCircuitBytes', u64be],
  ['maxConcurrentStreams', u16be],
  ['maxRelayCount', ranged(u8, 2, 4, 'maxRelayCount')],
  ['hopAdmissionProfileId', profileId],
  ['issuedEpoch', u32be],
  ['expiresEpoch', u32be],
  ['routeNonce', bytes32],
  ['previousSignature', bytes64]
], {
  name: 'BlindTransportRouteV1',
  validate (value) {
    validateEpochWindow(value)
    if ((value.envelopeClassBits & ~0x7e) !== 0) fail('envelopeClassBits contains a reserved bit')
    if ((value.wireClassBits & ~0x0e) !== 0) fail('wireClassBits contains a reserved bit')
    if (value.maxCanonicalDispatchBytes > DISPATCH_LIMITS.MAX_WIRE_BYTES) {
      fail('maxCanonicalDispatchBytes exceeds the absolute dispatch cap')
    }
    if (value.maxOpenBytes > 128 * KiB) fail('maxOpenBytes exceeds 128 KiB')
    if (value.maxConcurrentStreams > 1024) fail('maxConcurrentStreams exceeds 1024')
    if (value.routeKind === 1) {
      if (value.envelopeClassBits === 0 || value.maxEncapsulatedRequestBytes === 0) {
        fail('OHTTP routes require envelope classes and an encapsulated request cap')
      }
      if (value.wireClassBits !== 0 || value.maxOpenBytes !== 0 ||
          bigint(value.maxCircuitBytes, 'maxCircuitBytes') !== 0n || value.maxConcurrentStreams !== 0) {
        fail('OHTTP routes must zero streaming-only fields')
      }
    } else {
      if (value.maxEncapsulatedRequestBytes !== 0) fail('non-OHTTP routes must zero maxEncapsulatedRequestBytes')
      if (value.routeKind >= 2 && value.routeKind <= 5 &&
          (value.wireClassBits === 0 || value.maxOpenBytes === 0 ||
           bigint(value.maxCircuitBytes, 'maxCircuitBytes') === 0n || value.maxConcurrentStreams === 0)) {
        fail('streaming routes require nonzero wire/open/circuit/stream caps')
      }
    }
  }
})

export const blindForwardRouteHopV1 = /* @__PURE__ */ (() => struct([
  ['hopIndex', ranged(u8, 0, 3, 'hopIndex')],
  ['relayPublicKey', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['previousScopeHash', bytes32],
  ['scopeHash', bytes32],
  ['relaySignature', bytes64]
], {
  name: 'BlindForwardRouteHopV1',
  validate (value) {
    assertNonzeroBytes(value.relayPublicKey, 'relayPublicKey')
    assertNonzeroBytes(value.descriptorHash, 'descriptorHash')
    assertNonzeroBytes(value.scopeHash, 'scopeHash')
    if (value.hopIndex === 0 && !isAllZero(value.previousScopeHash)) {
      fail('route-scope hop zero requires an all-zero previousScopeHash')
    }
    if (value.hopIndex !== 0 && isAllZero(value.previousScopeHash)) {
      fail('route-scope continuation requires a nonzero previousScopeHash')
    }
  }
}))()

const blindForwardRouteHopsV1 = /* @__PURE__ */ (() => arrayOf(
  blindForwardRouteHopV1, 1, 4, 'forward route-scope hops'))()

export const blindForwardRouteScopeV1 = /* @__PURE__ */ (() => struct([
  ['version', version1],
  ['rootRouteId', bytes16],
  ['rootCircuitNonce', bytes32],
  ['rootRequestCommitment', bytes32],
  ['maxRelayCount', ranged(u8, 2, 4, 'maxRelayCount')],
  ['expiresEpoch', u32be],
  ['hops', blindForwardRouteHopsV1]
], {
  name: 'BlindForwardRouteScopeV1',
  validate (value) {
    assertNonzeroBytes(value.rootRouteId, 'rootRouteId')
    assertNonzeroBytes(value.rootCircuitNonce, 'rootCircuitNonce')
    assertNonzeroBytes(value.rootRequestCommitment, 'rootRequestCommitment')
    if (value.expiresEpoch === 0) fail('route-scope expiresEpoch must be nonzero')
    if (value.hops.length > value.maxRelayCount) fail('route-scope relay count exceeds maxRelayCount')
    const relayKeys = new Set()
    for (let index = 0; index < value.hops.length; index++) {
      const hop = value.hops[index]
      if (hop.hopIndex !== index) fail('route-scope hop indexes must be contiguous from zero')
      if (index > 0 && !b4a.equals(hop.previousScopeHash, value.hops[index - 1].scopeHash)) {
        fail('route-scope previousScopeHash does not bind the complete prefix')
      }
      const relayKey = b4a.toString(hop.relayPublicKey, 'hex')
      if (relayKeys.has(relayKey)) fail('route-scope repeats a relay public key')
      relayKeys.add(relayKey)
    }
  }
}))()

export const blindForwardHopOpenV1 = /* @__PURE__ */ (() => struct([
  ['version', version1],
  ['route', blindTransportRouteV1],
  ['routeScope', blindForwardRouteScopeV1],
  ['previousDescriptorSequence', u64be],
  ['previousDescriptorHash', bytes32],
  ['circuitNonce', bytes32],
  ['requestedWireClass', wireClass],
  ['circuitClass', circuitClass],
  ['grantedInitialWindow', u32be],
  ['maxDataBytes', u32be],
  ['maxCircuitBytes', u64be],
  ['idleMillis', u32be],
  ['lifetimeMillis', u32be],
  ['clientRequestCommitment', bytes32],
  ['handshakeFlight1', bytes32],
  ['forwarderSignature', bytes64]
], {
  name: 'BlindForwardHopOpenV1',
  validate (value) {
    validateForwardTuple(value)
    if (value.route.routeKind < 2 || value.route.routeKind > 5) {
      fail('BlindForwardHopOpenV1 requires a streaming route')
    }
    if ((value.route.wireClassBits & (1 << value.requestedWireClass)) === 0) {
      fail('requestedWireClass is not admitted by the route')
    }
    if (bigint(value.maxCircuitBytes, 'maxCircuitBytes') > bigint(value.route.maxCircuitBytes, 'route.maxCircuitBytes')) {
      fail('forward circuit exceeds the route byte cap')
    }
    const lastHop = value.routeScope.hops[value.routeScope.hops.length - 1]
    if (!b4a.equals(lastHop.relayPublicKey, value.route.previousRelayKey) ||
        bigint(lastHop.descriptorSequence, 'routeScope descriptorSequence') !==
          bigint(value.previousDescriptorSequence, 'previousDescriptorSequence') ||
        !b4a.equals(lastHop.descriptorHash, value.previousDescriptorHash)) {
      fail('BlindForwardHopOpenV1 route scope does not end at the forwarding relay descriptor')
    }
    if (value.routeScope.hops.length > value.route.maxRelayCount) {
      fail('BlindForwardHopOpenV1 route scope exceeds the signed route relay bound')
    }
  }
}))()

export const blindForwardHopAcceptV1 = /* @__PURE__ */ (() => struct([
  ['version', version1],
  ['previousRelayKey', bytes32],
  ['previousDescriptorSequence', u64be],
  ['previousDescriptorHash', bytes32],
  ['nextRelayKey', bytes32],
  ['nextDescriptorSequence', u64be],
  ['nextDescriptorHash', bytes32],
  ['nextRelayBinding', relayResultBindingV1],
  ['routeId', bytes16],
  ['circuitNonce', bytes32],
  ['nextStreamId', u64be],
  ['grantedWireClass', wireClass],
  ['circuitClass', circuitClass],
  ['grantedInitialWindow', u32be],
  ['maxDataBytes', u32be],
  ['maxCircuitBytes', u64be],
  ['idleMillis', u32be],
  ['lifetimeMillis', u32be],
  ['openedAtEpoch', u32be],
  ['hopOpenCommitment', bytes32],
  ['acceptedRouteScopeHash', bytes32],
  ['acceptedRelayCount', ranged(u8, 1, 4, 'acceptedRelayCount')],
  ['handshakeFlight2', bytes96],
  ['nextSignature', bytes64]
], {
  name: 'BlindForwardHopAcceptV1',
  validate (value) {
    validateForwardTuple(value)
    if (bigint(value.nextStreamId, 'nextStreamId') === 0n) fail('nextStreamId must be nonzero')
    if (!b4a.equals(value.nextRelayKey, value.nextRelayBinding.relayPublicKey) ||
        bigint(value.nextDescriptorSequence, 'nextDescriptorSequence') !==
          bigint(value.nextRelayBinding.descriptorSequence, 'binding descriptorSequence') ||
        !b4a.equals(value.nextDescriptorHash, value.nextRelayBinding.descriptorHash)) {
      fail('nextRelayBinding does not match the accepted next relay descriptor')
    }
  }
}))()

export const coreOpenReplicationV1 = struct([
  ['version', version1],
  ['wireProfileHash', bytes32],
  ['sessionClass', sessionClass],
  ['controlChannelId', u64be],
  ['parentChannelBinding', bytes32],
  ['clientNonce', bytes32],
  ['admission', admissionV1]
], {
  name: 'CoreOpenReplicationV1',
  validate (value) {
    if (bigint(value.controlChannelId, 'controlChannelId') === 0n) fail('controlChannelId must be nonzero')
    if (isAllZero(value.parentChannelBinding)) fail('parentChannelBinding must be nonzero')
  }
})

export const coreOpenReplicationResultV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['wireProfileHash', bytes32],
  ['sessionClass', sessionClass],
  ['controlChannelId', u64be],
  ['parentChannelBinding', bytes32],
  ['streamId', u64be],
  ['maxSessionBytes', u64be],
  ['idleMillis', u32be],
  ['lifetimeMillis', u32be],
  ['openedAtEpoch', u32be],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['signature', bytes64]
], {
  name: 'CoreOpenReplicationResultV1',
  validate (value) {
    validateCoreTuple(value)
    if (bigint(value.controlChannelId, 'controlChannelId') === 0n) fail('controlChannelId must be nonzero')
    if (bigint(value.streamId, 'streamId') === 0n) fail('streamId must be nonzero')
    if (isAllZero(value.parentChannelBinding)) fail('parentChannelBinding must be nonzero')
  }
})

// Kept here for subsequent operation codecs so every fixed identity field uses
// the same zero-copy primitive and no schema silently chooses another encoding.
export const fixed16 = bytes16
export const fixed32 = bytes32

const conformanceClass = ranged(u8, ADMISSION_CONFORMANCE_CLASS.OPEN,
  ADMISSION_CONFORMANCE_CLASS.PRIVATE, 'conformanceClass')
const roleBits = u16be
const operationBits = u32be
const parameterUrl = canonicalHttpsUrlBytes('parameterUrl')
const issuanceUrl = canonicalHttpsUrlBytes('issuanceUrl')
const descriptorUrl = canonicalHttpsUrlBytes('descriptorUrl')

export const admissionProfileV1 = struct([
  ['profileId', profileId],
  ['schemeId', schemeId],
  ['conformanceClass', conformanceClass],
  ['roleBits', roleBits],
  ['parameterUrl', optional(parameterUrl, 'parameterUrl')],
  ['parameterHash', bytes32]
], {
  name: 'AdmissionProfileV1',
  validate (value) {
    if (value.roleBits === 0 || (value.roleBits & ~ENDPOINT_LIMITS.ROLE_BITS_MASK) !== 0) {
      fail('admission roleBits must contain known nonzero bits')
    }
  }
})

export const admissionResourceCostV1 = struct([
  ['familyId', ranged(u8, 1, 5, 'resource cost familyId')],
  ['operationId', ranged(u8, 1, 255, 'resource cost operationId')],
  ['resourceClass', u8],
  ['leaseClass', optionalLeaseClass],
  ['costUnits', u64be]
], {
  name: 'AdmissionParametersV1.resourceCost',
  validate (value) {
    if (bigint(value.costUnits, 'costUnits') === 0n) fail('costUnits must be nonzero')
  }
})

const admissionResourceCostsV1 = arrayOf(admissionResourceCostV1, 1,
  PUBLIC_PROFILE_LIMITS.MAX_ADMISSION_RESOURCE_COST_ROWS, 'admission resource costs')

function compareResourceCost (a, b) {
  for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
    const compared = compareScalar(a[field], b[field])
    if (compared !== 0) return compared
  }
  return 0
}

const admissionParametersBaseV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['profileId', profileId],
  ['schemeId', schemeId],
  ['conformanceClass', conformanceClass],
  ['roleBits', roleBits],
  ['verifierKey', boundedBytes(0, 4096, 'verifierKey')],
  ['resourceCosts', admissionResourceCostsV1],
  ['tokenMaxBytes', ranged(u16be, 1, PUBLIC_PROFILE_LIMITS.MAX_ADMISSION_TOKEN_BYTES, 'tokenMaxBytes')],
  ['issuanceUrl', optional(issuanceUrl, 'issuanceUrl')],
  ['issuerRelayKey', optional(bytes32, 'issuerRelayKey')],
  ['validFromEpoch', u32be],
  ['expiresEpoch', u32be],
  ['nonce', bytes32],
  ['signature', bytes64]
], {
  name: 'AdmissionParametersV1',
  validate (value) {
    assertNonzeroBytes(value.relayPublicKey, 'relayPublicKey')
    if (value.roleBits === 0 || (value.roleBits & ~ENDPOINT_LIMITS.ROLE_BITS_MASK) !== 0) {
      fail('admission roleBits must contain known nonzero bits')
    }
    assertStrictlySorted(value.resourceCosts, compareResourceCost, 'admission resource costs')
    if ((value.issuanceUrl == null) !== (value.issuerRelayKey == null)) {
      fail('issuanceUrl and issuerRelayKey must be present together')
    }
    if (value.issuerRelayKey != null) assertNonzeroBytes(value.issuerRelayKey, 'issuerRelayKey')
    if (value.validFromEpoch >= value.expiresEpoch) fail('admission parameter validity window must be nonempty')
  }
})

export const admissionParametersV1 = cappedEncoding(admissionParametersBaseV1, 16 * KiB, 'AdmissionParametersV1')

export const relayIdentityTransitionV1 = struct([
  ['version', version1],
  ['oldRelayKey', bytes32],
  ['newRelayKey', bytes32],
  ['oldIdentitySequence', u64be],
  ['newIdentitySequence', u64be],
  ['validFromEpoch', u32be],
  ['reasonCode', ranged(u8, 1, 3, 'identity transition reasonCode')],
  ['transitionNonce', bytes32],
  ['oldSignature', bytes64],
  ['newSignature', bytes64]
], {
  name: 'RelayIdentityTransitionV1',
  validate (value) {
    assertNonzeroBytes(value.oldRelayKey, 'oldRelayKey')
    assertNonzeroBytes(value.newRelayKey, 'newRelayKey')
    if (b4a.equals(value.oldRelayKey, value.newRelayKey)) fail('identity transition relay keys must differ')
    if (bigint(value.oldIdentitySequence, 'oldIdentitySequence') === MAX_U64 ||
        bigint(value.newIdentitySequence, 'newIdentitySequence') !==
          bigint(value.oldIdentitySequence, 'oldIdentitySequence') + 1n) {
      fail('newIdentitySequence must equal oldIdentitySequence + 1')
    }
  }
})

const blindDhtPointerBaseV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['descriptorUrl', descriptorUrl],
  ['transportBits', u16be],
  ['issuedEpoch', u32be],
  ['expiresEpoch', u32be],
  ['nonce', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindDhtPointerV1',
  validate (value) {
    assertNonzeroBytes(value.relayPublicKey, 'relayPublicKey')
    if (value.transportBits === 0 || (value.transportBits & ~PUBLIC_PROFILE_LIMITS.TRANSPORT_BITS_MASK) !== 0) {
      fail('transportBits must contain known nonzero bits')
    }
    validateEpochWindow(value)
  }
})

export const blindDhtPointerV1 = cappedEncoding(blindDhtPointerBaseV1,
  PUBLIC_PROFILE_LIMITS.MAX_DHT_POINTER_BYTES, 'BlindDhtPointerV1')

export const blindOhttpKeyConfigV1 = struct([
  ['version', version1],
  ['gatewayRelayKey', bytes32],
  ['gatewayDescriptorSequence', u64be],
  ['configId', u8],
  ['kemId', ranged(u16be, 1, 0xffff, 'kemId')],
  ['kdfId', ranged(u16be, 1, 0xffff, 'kdfId')],
  ['aeadId', ranged(u16be, 1, 0xffff, 'aeadId')],
  ['encodedPublicKey', boundedBytes(1, 256, 'encodedPublicKey')],
  ['notBeforeEpoch', u32be],
  ['notAfterEpoch', u32be],
  ['previousConfigHash', optional(bytes32, 'previousConfigHash')],
  ['signature', bytes64]
], {
  name: 'BlindOhttpKeyConfigV1',
  validate (value) {
    assertNonzeroBytes(value.gatewayRelayKey, 'gatewayRelayKey')
    if (value.notBeforeEpoch >= value.notAfterEpoch ||
        value.notAfterEpoch - value.notBeforeEpoch > PUBLIC_PROFILE_LIMITS.MAX_OHTTP_CONFIG_EPOCHS) {
      fail('OHTTP key validity must be within 1..120 epochs')
    }
  }
})

export const blindHealthChallengeV1 = struct([
  ['version', version1],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['endpointId', endpointId],
  ['transportSupportBit', transportSupportBit],
  ['requestedRoleBits', roleBits],
  ['requestedOperationBits', operationBits],
  ['clientNonce', bytes32]
], {
  name: 'BlindHealthChallengeV1',
  validate (value) {
    if ((value.transportSupportBit & (value.transportSupportBit - 1)) !== 0) {
      fail('transportSupportBit must be one frozen one-hot support bit')
    }
    if ((value.requestedRoleBits & ~ENDPOINT_LIMITS.ROLE_BITS_MASK) !== 0) {
      fail('requestedRoleBits contains a reserved bit')
    }
    if ((value.requestedOperationBits & ~PUBLIC_PROFILE_LIMITS.ENABLED_OPERATION_BITS_MASK) !== 0) {
      fail('requestedOperationBits contains a reserved bit')
    }
    if (value.requestedRoleBits === 0 || value.requestedOperationBits === 0) {
      fail('health challenge role and operation bitmaps must both be nonzero')
    }
  }
})

export const blindHealthResultV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['endpointId', endpointId],
  ['transportSupportBit', transportSupportBit],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['clientNonce', bytes32],
  ['readyRoleBits', roleBits],
  ['readyOperationBits', operationBits],
  ['clockState', ranged(u8, HEALTH_CLOCK_STATE.READY, HEALTH_CLOCK_STATE.VERIFYING, 'clockState')],
  ['effectiveEpochFloor', u32be],
  ['integrityState', ranged(u8, HEALTH_INTEGRITY_STATE.VERIFIED, HEALTH_INTEGRITY_STATE.FAILED, 'integrityState')],
  ['checkpointAgeBand', ranged(u8, 0, 7, 'checkpointAgeBand')],
  ['scrubAgeBand', ranged(u8, 0, 7, 'scrubAgeBand')],
  ['rebalanceState', ranged(u8, HEALTH_REBALANCE_STATE.STABLE, HEALTH_REBALANCE_STATE.FENCED, 'rebalanceState')],
  ['capacityBand', ranged(u8, 0, 7, 'capacityBand')],
  ['challengeEpoch', u32be],
  ['signature', bytes64]
], {
  name: 'BlindHealthResultV1',
  validate (value) {
    assertNonzeroBytes(value.relayPublicKey, 'relayPublicKey')
    assertNonzeroBytes(value.storeId, 'storeId')
    if ((value.transportSupportBit & (value.transportSupportBit - 1)) !== 0) {
      fail('transportSupportBit must be one frozen one-hot support bit')
    }
    if ((value.readyRoleBits & ~ENDPOINT_LIMITS.ROLE_BITS_MASK) !== 0) {
      fail('readyRoleBits contains a reserved bit')
    }
    if ((value.readyOperationBits & ~PUBLIC_PROFILE_LIMITS.ENABLED_OPERATION_BITS_MASK) !== 0) {
      fail('readyOperationBits contains a reserved bit')
    }
  }
})

export const blindExternalBackupFailureGroupV1 = struct([
  ['backupFailureGroupId', bytes32],
  ['operatorGroupId', bytes32]
], {
  name: 'BlindExternalJournalTopologyV1.backupFailureGroup',
  validate (value) {
    assertNonzeroBytes(value.backupFailureGroupId, 'backupFailureGroupId')
    assertNonzeroBytes(value.operatorGroupId, 'backup operatorGroupId')
  }
})

export const blindExternalJournalNodeV1 = struct([
  ['nodePublicKey', bytes32],
  ['operatorGroupId', bytes32],
  ['failureDomainId', bytes32],
  ['roleConflictBits', u16be]
], {
  name: 'BlindExternalJournalTopologyV1.node',
  validate (value) {
    assertNonzeroBytes(value.nodePublicKey, 'journal nodePublicKey')
    assertNonzeroBytes(value.operatorGroupId, 'journal operatorGroupId')
    assertNonzeroBytes(value.failureDomainId, 'journal failureDomainId')
  }
})

const externalBackupFailureGroupsV1 = arrayOf(blindExternalBackupFailureGroupV1, 0, 16,
  'external backup failure groups')
const externalJournalNodesV1 = arrayOf(blindExternalJournalNodeV1, 3, 3, 'external journal nodes')

function compareBackupFailureGroup (a, b) {
  return compareBytes(a.backupFailureGroupId, b.backupFailureGroupId) ||
    compareBytes(a.operatorGroupId, b.operatorGroupId)
}

function compareJournalNode (a, b) {
  return compareBytes(a.nodePublicKey, b.nodePublicKey) ||
    compareBytes(a.operatorGroupId, b.operatorGroupId) ||
    compareBytes(a.failureDomainId, b.failureDomainId) ||
    compareScalar(a.roleConflictBits, b.roleConflictBits)
}

export const blindExternalJournalTopologyV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['topologySequence', u64be],
  ['previousTopologyHash', optional(bytes32, 'previousTopologyHash')],
  ['replicationClass', constant(u8, 1, 'replicationClass')],
  ['commitQuorum', constant(u8, 2, 'commitQuorum')],
  ['sharedFailureGroupId', bytes32],
  ['liveStoreFailureGroupId', bytes32],
  ['backupFailureGroups', externalBackupFailureGroupsV1],
  ['nodes', externalJournalNodesV1],
  ['issuedEpoch', u32be],
  ['expiresEpoch', u32be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindExternalJournalTopologyV1',
  validate (value) {
    for (const field of [
      'relayPublicKey',
      'storeId',
      'externalJournalId',
      'durabilityContinuityHash',
      'sharedFailureGroupId',
      'liveStoreFailureGroupId',
      'witnessPublicKey'
    ]) assertNonzeroBytes(value[field], field)
    const sequence = bigint(value.topologySequence, 'topologySequence')
    if ((sequence === 0n) !== (value.previousTopologyHash == null)) {
      fail('previousTopologyHash must be absent exactly for topology sequence zero')
    }
    assertStrictlySorted(value.backupFailureGroups, compareBackupFailureGroup, 'backup failure groups')
    assertStrictlySorted(value.nodes, compareJournalNode, 'external journal nodes')
    assertDistinctBytes(value.nodes.map(node => node.operatorGroupId), 'journal operator groups')
    assertDistinctBytes(value.nodes.map(node => node.failureDomainId), 'journal failure domains')
    validateEpochWindow(value)
  }
})

export const blindCoreAckV1 = struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['corePublicKey', bytes32],
  ['fork', u64be],
  ['length', u64be],
  ['signedHeadHash', bytes32],
  ['observedAtEpoch', u32be],
  ['leaseEpoch', u32be],
  ['result', ranged(u8, CORE_ACK_RESULT.MIRROR_ACCEPTED, CORE_ACK_RESULT.RECENTLY_SERVED, 'core ack result')],
  ['requestNonce', bytes32],
  ['requestCommitment', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindCoreAckV1',
  validate (value) {
    assertNonzeroBytes(value.corePublicKey, 'corePublicKey')
    assertNonzeroBytes(value.signedHeadHash, 'signedHeadHash')
  }
})

export const coreMirrorRequestV1 = struct([
  ['version', version1],
  ['corePublicKey', bytes32],
  ['fork', u64be],
  ['length', u64be],
  ['signedHeadHash', bytes32],
  ['leaseClass', leaseClass],
  ['clientNonce', bytes32],
  ['admission', admissionV1]
], {
  name: 'CoreMirrorRequestV1',
  validate (value) {
    assertNonzeroBytes(value.corePublicKey, 'corePublicKey')
    assertNonzeroBytes(value.signedHeadHash, 'signedHeadHash')
    if (bigint(value.length, 'length') === 0n) fail('core mirror length must be nonzero')
  }
})

const coreBlockIndicesV1 = arrayOf(u64be, 1, 16, 'core block indices')

export const coreServeChallengeV1 = struct([
  ['version', version1],
  ['corePublicKey', bytes32],
  ['fork', u64be],
  ['length', u64be],
  ['signedHeadHash', bytes32],
  ['blockIndices', coreBlockIndicesV1],
  ['clientNonce', bytes32],
  ['admission', optional(admissionV1, 'admission')]
], {
  name: 'CoreServeChallengeV1',
  validate (value) {
    assertNonzeroBytes(value.corePublicKey, 'corePublicKey')
    assertNonzeroBytes(value.signedHeadHash, 'signedHeadHash')
    const length = bigint(value.length, 'length')
    if (length === 0n) fail('core serve length must be nonzero')
    assertStrictlySorted(value.blockIndices, (a, b) => compareScalar(bigint(a, 'block index'), bigint(b, 'block index')),
      'core block indices')
    if (value.blockIndices.some(index => bigint(index, 'block index') >= length)) {
      fail('core block index must be below length')
    }
  }
})

const coreServeResultBaseV1 = struct([
  ['version', version1],
  ['acknowledgement', blindCoreAckV1],
  ['proofsAndBlocks', boundedBytes(1, 4 * MiB - 256, 'proofsAndBlocks')]
], {
  name: 'CoreServeResultV1',
  validate (value) {
    if (value.acknowledgement.result !== CORE_ACK_RESULT.RECENTLY_SERVED) {
      fail('core serve acknowledgement result must be RECENTLY_SERVED')
    }
  }
})

export const coreServeResultV1 = cappedEncoding(coreServeResultBaseV1, 4 * MiB, 'CoreServeResultV1')

export const blindForwardOpenV1 = /* @__PURE__ */ (() => struct([
  ['version', version1],
  ['routeId', bytes16],
  ['nextDescriptorSequence', u64be],
  ['nextDescriptorHash', bytes32],
  ['requestedWireClass', wireClass],
  ['circuitClass', circuitClass],
  ['circuitNonce', bytes32],
  ['parentRouteScopeHash', bytes32],
  ['hopAdmission', admissionV1],
  ['innerHandshake', boundedBytes(32, 32, 'innerHandshake')]
], {
  name: 'BlindForwardOpenV1',
  validate (value) {
    assertNonzeroBytes(value.routeId, 'routeId')
    assertNonzeroBytes(value.nextDescriptorHash, 'nextDescriptorHash')
    assertNonzeroBytes(value.circuitNonce, 'circuitNonce')
  }
}))()

export const blindForwardOpenResultV1 = /* @__PURE__ */ (() => struct([
  ['version', version1],
  ['relayBinding', relayResultBindingV1],
  ['routeId', bytes16],
  ['nextDescriptorSequence', u64be],
  ['nextDescriptorHash', bytes32],
  ['circuitNonce', bytes32],
  ['grantedWireClass', wireClass],
  ['circuitClass', circuitClass],
  ['streamId', u64be],
  ['grantedInitialWindow', u32be],
  ['maxDataBytes', u32be],
  ['maxCircuitBytes', u64be],
  ['idleMillis', u32be],
  ['lifetimeMillis', u32be],
  ['openedAtEpoch', u32be],
  ['requestCommitment', bytes32],
  ['acceptedRouteScopeHash', bytes32],
  ['acceptedRelayCount', ranged(u8, 1, 4, 'acceptedRelayCount')],
  ['nextHopAccept', blindForwardHopAcceptV1],
  ['signature', bytes64]
], {
  name: 'BlindForwardOpenResultV1',
  validate (value) {
    validateForwardTuple(value)
    if (bigint(value.streamId, 'streamId') === 0n) fail('streamId must be nonzero')
    for (const field of ['routeId', 'nextDescriptorHash', 'circuitNonce', 'requestCommitment']) {
      assertNonzeroBytes(value[field], field)
    }
    const next = value.nextHopAccept
    if (!b4a.equals(value.relayBinding.relayPublicKey, next.previousRelayKey) ||
        !b4a.equals(value.routeId, next.routeId) ||
        !b4a.equals(value.nextDescriptorHash, next.nextDescriptorHash) ||
        !b4a.equals(value.circuitNonce, next.circuitNonce) ||
        bigint(value.nextDescriptorSequence, 'nextDescriptorSequence') !==
          bigint(next.nextDescriptorSequence, 'nextDescriptorSequence') ||
        value.grantedWireClass !== next.grantedWireClass || value.circuitClass !== next.circuitClass ||
        value.grantedInitialWindow !== next.grantedInitialWindow || value.maxDataBytes !== next.maxDataBytes ||
        bigint(value.maxCircuitBytes, 'maxCircuitBytes') !== bigint(next.maxCircuitBytes, 'next maxCircuitBytes') ||
        value.idleMillis !== next.idleMillis || value.lifetimeMillis !== next.lifetimeMillis ||
        value.openedAtEpoch !== next.openedAtEpoch ||
        !b4a.equals(value.acceptedRouteScopeHash, next.acceptedRouteScopeHash) ||
        value.acceptedRelayCount !== next.acceptedRelayCount) {
      fail('forward open result does not match nextHopAccept')
    }
  }
}))()

export const blindForwardDataV1 = struct([
  ['version', version1],
  ['circuitNonce', bytes32],
  ['offset', u64be],
  ['bytes', boundedBytes(1, DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES, 'forward data bytes')]
], {
  name: 'BlindForwardDataV1',
  validate (value) {
    assertNonzeroBytes(value.circuitNonce, 'circuitNonce')
  }
})

export const blindForwardWindowV1 = struct([
  ['version', version1],
  ['circuitNonce', bytes32],
  ['consumedThrough', u64be],
  ['creditIncrement', ranged(u32be, 1, DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES, 'creditIncrement')]
], {
  name: 'BlindForwardWindowV1',
  validate (value) {
    assertNonzeroBytes(value.circuitNonce, 'circuitNonce')
  }
})

export const blindForwardCloseV1 = struct([
  ['version', version1],
  ['circuitNonce', bytes32],
  ['closeKind', ranged(u8, FORWARD_CLOSE_KIND.FIN, FORWARD_CLOSE_KIND.ABORT, 'closeKind')],
  ['finalSendOffset', u64be],
  ['reasonCode', u8]
], {
  name: 'BlindForwardCloseV1',
  validate (value) {
    assertNonzeroBytes(value.circuitNonce, 'circuitNonce')
  }
})

function streamChunkLengths (wireClassValue, contentLength) {
  const ciphertextLength = STREAM_WIRE_CLASS[wireClassValue]
  if (!ciphertextLength) fail('stream chunk wireClass is outside 1..3')
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) fail('contentLength is outside u32')
  const plaintextLength = ciphertextLength - 16
  const paddingLength = plaintextLength - 7 - contentLength
  if (paddingLength < 0) fail('contentLength exceeds the selected stream wire class')
  return { plaintextLength, paddingLength }
}

function validateStreamChunkPlain (value) {
  if (!value || typeof value !== 'object') fail('BlindStreamChunkPlainV1 must be an object')
  if (value.flags !== 0 && value.flags !== 1) fail('stream chunk flags contain a reserved bit')
  const lengths = streamChunkLengths(value.wireClass, value.contentLength)
  fixedBytes(value.contentLength, 'stream content').preencode({ end: 0 }, value.content)
  fixedBytes(lengths.paddingLength, 'stream randomPadding').preencode({ end: 0 }, value.randomPadding)
  return lengths
}

export const blindStreamChunkPlainV1 = {
  preencode (state, value) {
    const { plaintextLength } = validateStreamChunkPlain(value)
    version1.preencode(state, value.version)
    wireClass.preencode(state, value.wireClass)
    u8.preencode(state, value.flags)
    u32be.preencode(state, value.contentLength)
    fixedBytes(value.contentLength, 'stream content').preencode(state, value.content)
    fixedBytes(plaintextLength - 7 - value.contentLength, 'stream randomPadding').preencode(state, value.randomPadding)
  },
  encode (state, value) {
    const { paddingLength } = validateStreamChunkPlain(value)
    version1.encode(state, value.version)
    wireClass.encode(state, value.wireClass)
    u8.encode(state, value.flags)
    u32be.encode(state, value.contentLength)
    fixedBytes(value.contentLength, 'stream content').encode(state, value.content)
    fixedBytes(paddingLength, 'stream randomPadding').encode(state, value.randomPadding)
  },
  decode (state) {
    const value = {
      version: version1.decode(state),
      wireClass: wireClass.decode(state),
      flags: u8.decode(state),
      contentLength: u32be.decode(state)
    }
    const { paddingLength } = streamChunkLengths(value.wireClass, value.contentLength)
    value.content = fixedBytes(value.contentLength, 'stream content').decode(state)
    value.randomPadding = fixedBytes(paddingLength, 'stream randomPadding').decode(state)
    validateStreamChunkPlain(value)
    return value
  }
}

const descriptorProtocolsV1 = arrayOf(protocolProfileV1, 1, 16, 'descriptor protocols')
const descriptorEndpointsV1 = arrayOf(transportEndpointV1, 1, 16, 'descriptor endpoints')
const descriptorAdmissionProfilesV1 = arrayOf(admissionProfileV1, 1, 8, 'descriptor admission profiles')

const blindServiceDescriptorBaseV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['descriptorSequence', u64be],
  ['previousDescriptorHash', optional(bytes32, 'previousDescriptorHash')],
  ['identitySequence', u64be],
  ['previousRelayKey', optional(bytes32, 'previousRelayKey')],
  ['identityTransition', optional(relayIdentityTransitionV1, 'identityTransition')],
  ['build', buildProfileV1],
  ['protocols', descriptorProtocolsV1],
  ['endpoints', descriptorEndpointsV1],
  ['cellSizeClassBits', u8],
  ['leaseClassBits', u8],
  ['maxBatchCount', ranged(u16be, 1, PUBLIC_PROFILE_LIMITS.MAX_BATCH_COUNT, 'maxBatchCount')],
  ['maxResponseBytes', ranged(u32be, 1, PUBLIC_PROFILE_LIMITS.MAX_RESPONSE_BYTES, 'maxResponseBytes')],
  ['maxSponsoredCoreLength', u64be],
  ['enabledOperationBits', operationBits],
  ['admissionProfiles', descriptorAdmissionProfilesV1],
  ['durability', durabilityProfileV1],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['storeLifecycleState', ranged(u8, STORE_LIFECYCLE_STATE.ACTIVE, STORE_LIFECYCLE_STATE.RETIRED,
    'storeLifecycleState')],
  ['drainStartedEpoch', optional(u32be, 'drainStartedEpoch')],
  ['capacityBand', ranged(u8, 0, 7, 'capacityBand')],
  ['issuedEpoch', u32be],
  ['expiresEpoch', u32be],
  ['descriptorNonce', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindServiceDescriptorV1',
  validate (value) {
    for (const field of [
      'relayPublicKey',
      'storeId',
      'durabilityContinuityHash',
      'durabilityProfileHash',
      'descriptorNonce'
    ]) assertNonzeroBytes(value[field], field)

    const descriptorSequence = bigint(value.descriptorSequence, 'descriptorSequence')
    if ((descriptorSequence === 0n) !== (value.previousDescriptorHash == null)) {
      fail('previousDescriptorHash must be absent exactly for descriptor sequence zero')
    }
    const rotating = value.identityTransition != null
    if (rotating !== (value.previousRelayKey != null)) {
      fail('previousRelayKey and identityTransition must be present together')
    }
    if (rotating) {
      const transition = value.identityTransition
      if (!b4a.equals(value.previousRelayKey, transition.oldRelayKey) ||
          !b4a.equals(value.relayPublicKey, transition.newRelayKey) ||
          bigint(value.identitySequence, 'identitySequence') !==
            bigint(transition.newIdentitySequence, 'newIdentitySequence')) {
        fail('descriptor identity transition does not bind its current and previous identity')
      }
    }

    assertStrictlySorted(value.protocols, (a, b) => compareScalar(a.protocolId, b.protocolId),
      'descriptor protocols')
    assertStrictlySorted(value.endpoints, (a, b) => compareScalar(a.endpointId, b.endpointId),
      'descriptor endpoints')
    assertStrictlySorted(value.admissionProfiles, (a, b) => compareScalar(a.profileId, b.profileId),
      'descriptor admission profiles')

    if (value.cellSizeClassBits === 0 ||
        (value.cellSizeClassBits & ~PUBLIC_PROFILE_LIMITS.CELL_SIZE_CLASS_BITS_MASK) !== 0) {
      fail('cellSizeClassBits must contain known nonzero bits')
    }
    if (value.leaseClassBits === 0 ||
        (value.leaseClassBits & ~PUBLIC_PROFILE_LIMITS.LEASE_CLASS_BITS_MASK) !== 0) {
      fail('leaseClassBits must contain known nonzero bits')
    }
    if ((value.enabledOperationBits & ~PUBLIC_PROFILE_LIMITS.ENABLED_OPERATION_BITS_MASK) !== 0) {
      fail('enabledOperationBits contains a reserved bit')
    }

    const draining = value.storeLifecycleState === STORE_LIFECYCLE_STATE.DRAINING
    const retired = value.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED
    if ((value.storeLifecycleState === STORE_LIFECYCLE_STATE.ACTIVE) !== (value.drainStartedEpoch == null)) {
      fail('drainStartedEpoch presence does not match storeLifecycleState')
    }
    if (value.drainStartedEpoch != null && value.drainStartedEpoch > value.issuedEpoch) {
      fail('drainStartedEpoch cannot be after descriptor issuance')
    }
    if (draining && value.enabledOperationBits !== 0x000129d7) {
      fail('DRAINING descriptor has the wrong enabled operation bitmap')
    }
    if (retired && value.enabledOperationBits !== 0) fail('RETIRED descriptor must disable all operations')
    validateEpochWindow(value)
  }
})

export const blindServiceDescriptorV1 = cappedEncoding(blindServiceDescriptorBaseV1,
  PUBLIC_PROFILE_LIMITS.MAX_DESCRIPTOR_BYTES, 'BlindServiceDescriptorV1')

export const schemaCatalogEntryV1 = struct([
  ['category', ranged(u8, 1, 5, 'schema category')],
  ['categoryLocalSchemaId', ranged(u16be, 1, 0xffff, 'categoryLocalSchemaId')],
  ['schemaName', canonicalAsciiBytes(1, 96, 'schemaName')],
  ['canonicalSchemaBytes', boundedBytes(1, 0xffff, 'canonicalSchemaBytes')]
], {
  name: 'SchemaCatalogEntryV1',
  validate (value) {
    const hashes = SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY[value.category]
    const expectedHash = hashes && hashes[value.categoryLocalSchemaId - 1]
    if (!expectedHash ||
        !b4a.equals(blake2b256(value.schemaName), b4a.from(expectedHash, 'hex'))) {
      fail('schema catalog entry does not match the frozen category registry')
    }
  }
})

export const PUBLIC_FAMILY_SCHEMA_CODECS = /* @__PURE__ */ Object.freeze({
  AdmissionParametersV1: admissionParametersV1,
  AdmissionProfileV1: admissionProfileV1,
  BlindCoreAckV1: blindCoreAckV1,
  BlindDhtPointerV1: blindDhtPointerV1,
  BlindExternalJournalTopologyV1: blindExternalJournalTopologyV1,
  BlindForwardCloseV1: blindForwardCloseV1,
  BlindForwardDataV1: blindForwardDataV1,
  BlindForwardOpenResultV1: blindForwardOpenResultV1,
  BlindForwardOpenV1: blindForwardOpenV1,
  BlindForwardWindowV1: blindForwardWindowV1,
  BlindHealthChallengeV1: blindHealthChallengeV1,
  BlindHealthResultV1: blindHealthResultV1,
  BlindOhttpKeyConfigV1: blindOhttpKeyConfigV1,
  BlindServiceDescriptorV1: blindServiceDescriptorV1,
  BlindStreamChunkPlainV1: blindStreamChunkPlainV1,
  CoreMirrorRequestV1: coreMirrorRequestV1,
  CoreServeChallengeV1: coreServeChallengeV1,
  CoreServeResultV1: coreServeResultV1,
  RelayIdentityTransitionV1: relayIdentityTransitionV1,
  SchemaCatalogEntryV1: schemaCatalogEntryV1
})
