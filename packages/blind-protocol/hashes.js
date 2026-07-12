import b4a from 'b4a'
import sodium from './crypto.js'
import { arrayOf, encodeCanonical, fixedBytes } from './codec.js'
import { protocolError } from './errors.js'
import {
  DOMAIN_RECIPE,
  DOMAIN_PURPOSE,
  REQUEST_COMMITMENT_DOMAIN_ID,
  domainRegistryEntry,
  isKnownOperation
} from './wire-runtime-authority.js'

const HASH_BYTES = 32
const MAX_U64 = (1n << 64n) - 1n

export const HASH_DOMAIN = Object.freeze({
  SPEC: 'hiverelay.blind.spec-hash.v1',
  ABI: 'hiverelay.blind.abi-hash.v1',
  VECTOR_SET: 'hiverelay.blind.vector-set-hash.v1',
  EVIDENCE_FORMAT: 'hiverelay.blind.evidence-format-hash.v1',
  EVIDENCE_VECTOR_SET: 'hiverelay.blind.evidence-vector-set-hash.v1',
  STORE_FORMAT: 'hiverelay.blind.store-format-hash.v1',
  STORE_VECTOR_SET: 'hiverelay.blind.store-vector-set-hash.v1',
  CLIENT_COMPOSITION_FORMAT: 'hiverelay.blind.client-composition-format-hash.v1',
  CLIENT_COMPOSITION_VECTOR_SET: 'hiverelay.blind.client-composition-vector-set-hash.v1',
  LOCAL_CHECKPOINT: 'hiverelay.blind.local-checkpoint-hash.v1',
  CONTROL_SNAPSHOT: 'hiverelay.blind.control-snapshot.v1',
  BUILD_ARTIFACT: 'hiverelay.blind.build-artifact-hash.v1',
  BUILD_MANIFEST: 'hiverelay.blind.build-manifest-hash.v1',
  PROTOCOL_PROFILE: 'hiverelay.blind.protocol-profile-hash.v1',
  TRANSPORT_PROFILE: 'hiverelay.blind.transport-profile-hash.v1',
  DESCRIPTOR: 'hiverelay.blind.descriptor-hash.v1',
  ADMISSION_PARAMETERS: 'hiverelay.blind.admission-parameters-hash.v1',
  DURABILITY_PROFILE: 'hiverelay.blind.durability-profile-hash.v1',
  DURABILITY_CONTINUITY: 'hiverelay.blind.durability-continuity-hash.v1',
  PERSISTENT_RESULT: 'hiverelay.blind.persistent-result.v1',
  REQUEST: 'hiverelay.blind.request.v1',
  CORE_OPEN_RESULT: 'hiverelay.blind.core-open-result.v1'
})

function asBuffer (value, field) {
  if (typeof value === 'string') return b4a.from(value, 'utf8')
  if (!value || typeof value.byteLength !== 'number') {
    protocolError('BAD_ENCODING', `${field} must be bytes`)
  }
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function encodeU64 (value, field = 'u64 length') {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) protocolError('BAD_ENCODING', `${field} is invalid`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    protocolError('BAD_ENCODING', `${field} is invalid`)
  }
  const output = b4a.alloc(8)
  for (let i = 7; i >= 0; i--) {
    output[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function encodeUnsigned (value, bytes, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    protocolError('BAD_ENCODING', `${field} is outside its unsigned range`)
  }
  const output = b4a.alloc(bytes)
  for (let i = bytes - 1; i >= 0; i--) {
    output[i] = value & 0xff
    value = Math.floor(value / 0x100)
  }
  return output
}

const encodeU8 = (value, field) => encodeUnsigned(value, 1, 0xff, field)
const encodeU16 = (value, field) => encodeUnsigned(value, 2, 0xffff, field)
const encodeU32 = (value, field) => encodeUnsigned(value, 4, 0xffffffff, field)

function fixedBytesInput (value, length, field) {
  value = asBuffer(value, field)
  if (value.byteLength !== length) protocolError('BAD_ENCODING', `${field} must be exactly ${length} bytes`)
  return value
}

function nonzeroFixedBytesInput (value, length, field) {
  value = fixedBytesInput(value, length, field)
  if (isAllZero(value)) protocolError('BAD_ENCODING', `${field} must be nonzero`)
  return value
}

function isAllZero (value) {
  for (let i = 0; i < value.byteLength; i++) {
    if (value[i] !== 0) return false
  }
  return true
}

export function blake2b256 (bytes) {
  bytes = asBuffer(bytes, 'hash input')
  const output = b4a.alloc(HASH_BYTES)
  sodium.crypto_generichash(output, bytes)
  return output
}

export function domainLengthHash (domain, bytes) {
  if (typeof domain !== 'string' || domain.length === 0 || /[^\x20-\x7e]/.test(domain)) {
    protocolError('BAD_ENCODING', 'hash domain must be non-empty printable ASCII')
  }
  bytes = asBuffer(bytes, 'hash input')
  const preimage = b4a.concat([
    b4a.from(domain, 'ascii'),
    encodeU64(bytes.byteLength),
    bytes
  ])
  return blake2b256(preimage)
}

export function domainHash (domain, bytes) {
  if (typeof domain !== 'string' || domain.length === 0 || /[^\x20-\x7e]/.test(domain)) {
    protocolError('BAD_ENCODING', 'hash domain must be non-empty printable ASCII')
  }
  bytes = asBuffer(bytes, 'hash input')
  return blake2b256(b4a.concat([b4a.from(domain, 'ascii'), bytes]))
}

export const hashSpec = bytes => domainLengthHash(HASH_DOMAIN.SPEC, bytes)
export const hashAbi = bytes => domainLengthHash(HASH_DOMAIN.ABI, bytes)
export const hashVectorSet = bytes => domainLengthHash(HASH_DOMAIN.VECTOR_SET, bytes)
export const hashEvidenceFormat = bytes => domainLengthHash(HASH_DOMAIN.EVIDENCE_FORMAT, bytes)
export const hashEvidenceVectorSet = bytes => domainLengthHash(HASH_DOMAIN.EVIDENCE_VECTOR_SET, bytes)
export const hashStoreFormat = bytes => domainLengthHash(HASH_DOMAIN.STORE_FORMAT, bytes)
export const hashStoreVectorSet = bytes => domainLengthHash(HASH_DOMAIN.STORE_VECTOR_SET, bytes)
export const hashClientCompositionFormat = bytes => domainLengthHash(HASH_DOMAIN.CLIENT_COMPOSITION_FORMAT, bytes)
export const hashClientCompositionVectorSet = bytes => domainLengthHash(HASH_DOMAIN.CLIENT_COMPOSITION_VECTOR_SET, bytes)
export const localCheckpointHash = bytes => domainLengthHash(HASH_DOMAIN.LOCAL_CHECKPOINT, bytes)
export const controlSnapshotHash = bytes => domainLengthHash(HASH_DOMAIN.CONTROL_SNAPSHOT, bytes)
export const hashBuildArtifact = bytes => domainLengthHash(HASH_DOMAIN.BUILD_ARTIFACT, bytes)
export const hashBuildManifest = bytes => domainLengthHash(HASH_DOMAIN.BUILD_MANIFEST, bytes)
export const hashProtocolProfile = bytes => domainLengthHash(HASH_DOMAIN.PROTOCOL_PROFILE, bytes)
export const hashTransportProfile = bytes => domainLengthHash(HASH_DOMAIN.TRANSPORT_PROFILE, bytes)
export const serviceDescriptorHash = bytes => domainHash(HASH_DOMAIN.DESCRIPTOR, bytes)
export const admissionParametersHash = bytes => domainHash(HASH_DOMAIN.ADMISSION_PARAMETERS, bytes)
export const durabilityProfileHash = bytes => domainLengthHash(HASH_DOMAIN.DURABILITY_PROFILE, bytes)
export const durabilityContinuityHash = bytes => domainLengthHash(HASH_DOMAIN.DURABILITY_CONTINUITY, bytes)

export function persistentResultCommitment (familyId, operationId, unsignedPersistentResultBytes) {
  if (!isKnownOperation(familyId, operationId)) protocolError('BAD_ENCODING', 'persistent result references an unknown operation')
  const bytes = asBuffer(unsignedPersistentResultBytes, 'unsigned persistent result')
  return blake2b256(b4a.concat([
    b4a.from(HASH_DOMAIN.PERSISTENT_RESULT, 'ascii'),
    encodeU8(familyId, 'persistent result familyId'),
    encodeU8(operationId, 'persistent result operationId'),
    encodeU64(bytes.byteLength, 'unsigned persistent result length'),
    bytes
  ]))
}

export function coreOpenReplicationRequestCommitment (value) {
  if (!value || typeof value !== 'object') protocolError('BAD_ENCODING', 'core open commitment input must be an object')
  if (!Number.isSafeInteger(value.sessionClass) || value.sessionClass < 1 || value.sessionClass > 3) {
    protocolError('BAD_ENCODING', 'sessionClass is outside 1..3')
  }
  const parentChannelBinding = fixedBytesInput(value.parentChannelBinding, 32, 'parentChannelBinding')
  if (isAllZero(parentChannelBinding)) protocolError('BAD_ENCODING', 'parentChannelBinding must be nonzero')
  const controlChannelId = encodeU64(value.controlChannelId, 'controlChannelId')
  if (isAllZero(controlChannelId)) protocolError('BAD_ENCODING', 'controlChannelId must be nonzero')
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CORE_OPEN_REPLICATION, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.wireProfileHash, 32, 'wireProfileHash'),
    b4a.from([value.sessionClass]),
    controlChannelId,
    parentChannelBinding,
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function coreMirrorRequestCommitment (value) {
  if (!value || typeof value !== 'object') protocolError('BAD_ENCODING', 'core mirror commitment input must be an object')
  if (!Number.isSafeInteger(value.leaseClass) || value.leaseClass < 1 || value.leaseClass > 4) {
    protocolError('BAD_ENCODING', 'leaseClass is outside 1..4')
  }
  const length = encodeU64(value.length, 'length')
  if (isAllZero(length)) protocolError('BAD_ENCODING', 'length must be nonzero')
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CORE_MIRROR, [
    nonzeroFixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    nonzeroFixedBytesInput(value.corePublicKey, 32, 'corePublicKey'),
    encodeU64(value.fork, 'fork'),
    length,
    nonzeroFixedBytesInput(value.signedHeadHash, 32, 'signedHeadHash'),
    encodeU8(value.leaseClass, 'leaseClass'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

const coreCommitmentBlockIndices = arrayOf({
  preencode (state, value) {
    const bytes = encodeU64(value, 'block index')
    state.end += bytes.byteLength
  },
  encode (state, value) {
    const bytes = encodeU64(value, 'block index')
    b4a.copy(bytes, state.buffer, state.start)
    state.start += bytes.byteLength
  },
  decode () {
    throw new Error('core commitment block-index encoding is encode-only')
  }
}, 1, 16, 'core commitment block indices')

export function coreServeRequestCommitment (value) {
  if (!value || typeof value !== 'object') protocolError('BAD_ENCODING', 'core serve commitment input must be an object')
  const length = encodeU64(value.length, 'length')
  if (isAllZero(length)) protocolError('BAD_ENCODING', 'length must be nonzero')
  if (!Array.isArray(value.blockIndices)) protocolError('BAD_ENCODING', 'blockIndices must be an array')
  let previous = -1n
  for (const index of value.blockIndices) {
    const encoded = encodeU64(index, 'block index')
    let current = 0n
    for (const byte of encoded) current = (current << 8n) | BigInt(byte)
    if (current <= previous) protocolError('BAD_ENCODING', 'blockIndices must be strictly sorted and duplicate-free')
    let requestedLength = 0n
    for (const byte of length) requestedLength = (requestedLength << 8n) | BigInt(byte)
    if (current >= requestedLength) protocolError('BAD_ENCODING', 'block index must be below length')
    previous = current
  }
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CORE_SERVE, [
    nonzeroFixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    nonzeroFixedBytesInput(value.corePublicKey, 32, 'corePublicKey'),
    encodeU64(value.fork, 'fork'),
    length,
    nonzeroFixedBytesInput(value.signedHeadHash, 32, 'signedHeadHash'),
    encodeCanonical(coreCommitmentBlockIndices, value.blockIndices),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function forwardOpenRequestCommitment (value) {
  if (!value || typeof value !== 'object') protocolError('BAD_ENCODING', 'forward open commitment input must be an object')
  if (!Number.isSafeInteger(value.requestedWireClass) || value.requestedWireClass < 1 || value.requestedWireClass > 3) {
    protocolError('BAD_ENCODING', 'requestedWireClass is outside 1..3')
  }
  if (!Number.isSafeInteger(value.circuitClass) || value.circuitClass < 1 || value.circuitClass > 3) {
    protocolError('BAD_ENCODING', 'circuitClass is outside 1..3')
  }
  const innerHandshake = fixedBytesInput(value.innerHandshake, 32, 'innerHandshake')
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.FORWARD_OPEN, [
    nonzeroFixedBytesInput(value.previousRelayKey, 32, 'previousRelayKey'),
    nonzeroFixedBytesInput(value.routeId, 16, 'routeId'),
    encodeU64(value.nextDescriptorSequence, 'nextDescriptorSequence'),
    nonzeroFixedBytesInput(value.nextDescriptorHash, 32, 'nextDescriptorHash'),
    encodeU8(value.requestedWireClass, 'requestedWireClass'),
    encodeU8(value.circuitClass, 'circuitClass'),
    nonzeroFixedBytesInput(value.circuitNonce, 32, 'circuitNonce'),
    fixedBytesInput(value.parentRouteScopeHash, 32, 'parentRouteScopeHash'),
    blake2b256(innerHandshake)
  ])
}

function requestCommitment (domainId, fields) {
  const entry = domainRegistryEntry(domainId)
  if (!entry || entry.purpose !== DOMAIN_PURPOSE.REQUEST_COMMITMENT ||
      entry.recipeId !== DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE) {
    protocolError('BAD_ENCODING', 'unknown request commitment domain')
  }
  return blake2b256(b4a.concat([
    b4a.from(entry.exactAsciiBytes, 'ascii'),
    ...fields
  ]))
}

export function allocationCommitment (value) {
  if (!value || typeof value !== 'object') protocolError('BAD_ENCODING', 'allocation commitment input must be an object')
  if (!Number.isSafeInteger(value.sizeClass) || value.sizeClass < 1 || value.sizeClass > 5) {
    protocolError('BAD_ENCODING', 'sizeClass is outside 1..5')
  }
  if (!Number.isSafeInteger(value.leaseClass) || value.leaseClass < 1 || value.leaseClass > 4) {
    protocolError('BAD_ENCODING', 'leaseClass is outside 1..4')
  }
  if (!b4a.equals(cellStorageSlot(value), fixedBytesInput(value.storageSlot, 32, 'storageSlot'))) {
    protocolError('BAD_ENCODING', 'storageSlot is not self-certifying')
  }
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.allocate.v1', 'ascii'),
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.storageSlot, 32, 'storageSlot'),
    encodeU32(value.allocationEpoch, 'allocationEpoch'),
    encodeU8(value.sizeClass, 'sizeClass'),
    encodeU8(value.leaseClass, 'leaseClass'),
    fixedBytesInput(value.declaredCellBlobHash, 32, 'declaredCellBlobHash'),
    fixedBytesInput(value.createPublicKey, 32, 'createPublicKey'),
    fixedBytesInput(value.renewPublicKey, 32, 'renewPublicKey'),
    fixedBytesInput(value.dropPublicKey, 32, 'dropPublicKey')
  ]))
}

export function cellStorageSlot (value) {
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.slot.v1', 'ascii'),
    encodeU32(value.allocationEpoch, 'allocationEpoch'),
    fixedBytesInput(value.createPublicKey, 32, 'createPublicKey')
  ]))
}

export function cellPutRequestCommitment (value) {
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CELL_PUT, [
    fixedBytesInput(value.allocationCommitment, 32, 'allocationCommitment'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function cellManageRequestCommitment (value) {
  if (value.operation !== 'cell-renew' && value.operation !== 'cell-drop') {
    protocolError('BAD_ENCODING', 'cell management operation is invalid')
  }
  if (!Number.isSafeInteger(value.requestedLeaseClass) || value.requestedLeaseClass < 0 || value.requestedLeaseClass > 4 ||
      (value.operation === 'cell-renew' && value.requestedLeaseClass === 0) ||
      (value.operation === 'cell-drop' && value.requestedLeaseClass !== 0)) {
    protocolError('BAD_ENCODING', 'requestedLeaseClass does not match the cell management operation')
  }
  const domainId = value.operation === 'cell-renew'
    ? REQUEST_COMMITMENT_DOMAIN_ID.CELL_RENEW
    : REQUEST_COMMITMENT_DOMAIN_ID.CELL_DROP
  return requestCommitment(domainId, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.storageSlot, 32, 'storageSlot'),
    encodeU64(value.expectedRevision, 'expectedRevision'),
    encodeU32(value.expectedLeaseEpoch, 'expectedLeaseEpoch'),
    encodeU8(value.requestedLeaseClass, 'requestedLeaseClass'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

function cellReadRequestCommitment (operation, value) {
  return requestCommitment(operation, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.storageSlot, 32, 'storageSlot'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export const cellGetRequestCommitment = value => cellReadRequestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CELL_GET, value)
export const cellProveRequestCommitment = value => cellReadRequestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CELL_PROVE, value)

const commitmentSlots = arrayOf(fixedBytes(32), 1, 64, 'commitment slots')

export function cellBatchGetRequestCommitment (value) {
  const slots = value && value.slots
  if (!Array.isArray(slots)) protocolError('BAD_ENCODING', 'slots must be an array')
  const seen = new Set()
  for (const slot of slots) {
    const bytes = fixedBytesInput(slot, 32, 'slot')
    const key = b4a.toString(bytes, 'hex')
    if (seen.has(key)) protocolError('BAD_ENCODING', 'slots contain a duplicate')
    seen.add(key)
  }
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.CELL_BATCH_GET, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce'),
    encodeCanonical(commitmentSlots, slots)
  ])
}

export function inboxPhysicalTopic (value) {
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.inbox-topic.v1', 'ascii'),
    encodeU32(value.allocationEpoch, 'allocationEpoch'),
    fixedBytesInput(value.createPublicKey, 32, 'createPublicKey')
  ]))
}

export function inboxCreateCommitment (value) {
  if (!Number.isSafeInteger(value.frameClassBits) || value.frameClassBits === 0 ||
      (value.frameClassBits & ~0x07) !== 0) {
    protocolError('BAD_ENCODING', 'frameClassBits must contain only advertised inbox classes')
  }
  if (!Number.isSafeInteger(value.appendAuthMode) || value.appendAuthMode < 0 || value.appendAuthMode > 1) {
    protocolError('BAD_ENCODING', 'appendAuthMode is outside 0..1')
  }
  if (!Number.isSafeInteger(value.retentionClass) || value.retentionClass < 1 || value.retentionClass > 4) {
    protocolError('BAD_ENCODING', 'retentionClass is outside 1..4')
  }
  if (!Number.isSafeInteger(value.leaseClass) || value.leaseClass < 1 || value.leaseClass > 4) {
    protocolError('BAD_ENCODING', 'leaseClass is outside 1..4')
  }
  if (!b4a.equals(inboxPhysicalTopic(value), fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'))) {
    protocolError('BAD_ENCODING', 'physicalTopic is not self-certifying')
  }
  const appendPublicKey = value.appendPublicKey == null
    ? b4a.alloc(32)
    : fixedBytesInput(value.appendPublicKey, 32, 'appendPublicKey')
  if ((value.appendAuthMode === 1) !== (value.appendPublicKey != null)) {
    protocolError('BAD_ENCODING', 'appendPublicKey presence does not match appendAuthMode')
  }
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.inbox-create.v1', 'ascii'),
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'),
    encodeU32(value.allocationEpoch, 'allocationEpoch'),
    encodeU8(value.frameClassBits, 'frameClassBits'),
    encodeU8(value.appendAuthMode, 'appendAuthMode'),
    appendPublicKey,
    fixedBytesInput(value.createPublicKey, 32, 'createPublicKey'),
    fixedBytesInput(value.renewPublicKey, 32, 'renewPublicKey'),
    fixedBytesInput(value.closePublicKey, 32, 'closePublicKey'),
    encodeU8(value.retentionClass, 'retentionClass'),
    encodeU8(value.leaseClass, 'leaseClass')
  ]))
}

export function inboxCreateRequestCommitment (value) {
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.INBOX_CREATE, [
    fixedBytesInput(value.inboxCreateCommitment, 32, 'inboxCreateCommitment'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function inboxManageRequestCommitment (value) {
  if (value.operation !== 'inbox-renew' && value.operation !== 'inbox-close') {
    protocolError('BAD_ENCODING', 'inbox management operation is invalid')
  }
  if (!Number.isSafeInteger(value.requestedLeaseClass) || value.requestedLeaseClass < 0 || value.requestedLeaseClass > 4 ||
      (value.operation === 'inbox-renew' && value.requestedLeaseClass === 0) ||
      (value.operation === 'inbox-close' && value.requestedLeaseClass !== 0)) {
    protocolError('BAD_ENCODING', 'requestedLeaseClass does not match the inbox management operation')
  }
  const domainId = value.operation === 'inbox-renew'
    ? REQUEST_COMMITMENT_DOMAIN_ID.INBOX_RENEW
    : REQUEST_COMMITMENT_DOMAIN_ID.INBOX_CLOSE
  return requestCommitment(domainId, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'),
    encodeU64(value.expectedRevision, 'expectedRevision'),
    encodeU32(value.expectedLeaseEpoch, 'expectedLeaseEpoch'),
    encodeU8(value.requestedLeaseClass, 'requestedLeaseClass'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function inboxAppendRequestCommitment (value) {
  if (!Number.isSafeInteger(value.frameClass) || value.frameClass < 1 || value.frameClass > 3) {
    protocolError('BAD_ENCODING', 'frameClass is outside 1..3')
  }
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.INBOX_APPEND, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'),
    encodeU8(value.frameClass, 'frameClass'),
    fixedBytesInput(value.frameHash, 32, 'frameHash'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function inboxReadRequestCommitment (value) {
  const cursor = asBuffer(value.cursor, 'cursor')
  if (cursor.byteLength > 128) protocolError('BAD_ENCODING', 'cursor exceeds 128 bytes')
  if (!Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 64) {
    protocolError('BAD_ENCODING', 'limit is outside 1..64')
  }
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.INBOX_READ, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'),
    blake2b256(cursor),
    encodeU16(value.limit, 'limit'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function inboxWatchRequestCommitment (value) {
  if (!Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 64) {
    protocolError('BAD_ENCODING', 'limit is outside 1..64')
  }
  if (!Number.isSafeInteger(value.maxWaitMillis) || value.maxWaitMillis < 1 || value.maxWaitMillis > 30000) {
    protocolError('BAD_ENCODING', 'maxWaitMillis is outside 1..30000')
  }
  return requestCommitment(REQUEST_COMMITMENT_DOMAIN_ID.INBOX_WATCH, [
    fixedBytesInput(value.relayPublicKey, 32, 'relayPublicKey'),
    fixedBytesInput(value.physicalTopic, 32, 'physicalTopic'),
    encodeU64(value.afterRevision, 'afterRevision'),
    encodeU16(value.limit, 'limit'),
    encodeU16(value.maxWaitMillis, 'maxWaitMillis'),
    fixedBytesInput(value.clientNonce, 32, 'clientNonce')
  ])
}

export function resultSignaturePayload (domainId, canonicalUnsignedBytes) {
  return signaturePayloadForPurpose(
    domainId,
    canonicalUnsignedBytes,
    DOMAIN_PURPOSE.RESULT_SIGNATURE,
    'result'
  )
}

export function auxiliarySignaturePayload (domainId, canonicalUnsignedBytes) {
  return signaturePayloadForPurpose(
    domainId,
    canonicalUnsignedBytes,
    DOMAIN_PURPOSE.AUXILIARY_SIGNATURE,
    'auxiliary'
  )
}

function signaturePayloadForPurpose (domainId, canonicalUnsignedBytes, purpose, label) {
  const entry = domainRegistryEntry(domainId)
  if (!entry || entry.purpose !== purpose || entry.recipeId !== DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD) {
    protocolError('BAD_ENCODING', `unknown ${label} signature domain`)
  }
  const payload = asBuffer(canonicalUnsignedBytes, `unsigned ${label} bytes`)
  return b4a.concat([
    b4a.from(entry.exactAsciiBytes, 'ascii'),
    encodeU64(payload.byteLength),
    payload
  ])
}

function validateVectorPath (path) {
  if (typeof path !== 'string' || path.length === 0) {
    protocolError('BAD_ENCODING', 'vector path must be a non-empty string')
  }
  if (path !== path.normalize('NFC')) protocolError('BAD_ENCODING', 'vector path must be NFC')
  if (path.startsWith('/') || path.includes('\\')) {
    protocolError('BAD_ENCODING', 'vector path must be relative and use slash separators')
  }
  const components = path.split('/')
  if (components.some(component => component === '' || component === '.' || component === '..')) {
    protocolError('BAD_ENCODING', 'vector path contains a forbidden component')
  }
  const bytes = b4a.from(path, 'utf8')
  if (bytes.byteLength > 0xffff) protocolError('TOO_LARGE', 'vector path exceeds u16')
  return bytes
}

function writeU16BE (buffer, value, offset) {
  buffer[offset] = (value >>> 8) & 0xff
  buffer[offset + 1] = value & 0xff
}

function requireManifestBytes (bytes, offset, length, field) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || length < 0 ||
      offset < 0 || offset + length > bytes.byteLength) {
    protocolError('BAD_ENCODING', `truncated vector manifest ${field}`)
  }
}

function readManifestU64 (bytes, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(bytes[offset + index])
  return value
}

export function encodeVectorManifest (entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    protocolError('BAD_ENCODING', 'vector manifest cannot be empty')
  }
  if (entries.length > 0xffffffff) protocolError('TOO_LARGE', 'too many vector entries')

  const normalized = entries.map(entry => {
    if (!entry || typeof entry !== 'object') protocolError('BAD_ENCODING', 'vector entry must be an object')
    const pathBytes = validateVectorPath(entry.path)
    const vectorBytes = asBuffer(entry.bytes, 'vector bytes')
    return {
      path: entry.path,
      pathBytes,
      vectorLength: vectorBytes.byteLength,
      vectorHash: blake2b256(vectorBytes)
    }
  }).sort((a, b) => b4a.compare(a.pathBytes, b.pathBytes))

  for (let i = 1; i < normalized.length; i++) {
    if (b4a.equals(normalized[i - 1].pathBytes, normalized[i].pathBytes)) {
      protocolError('BAD_ENCODING', 'duplicate normalized vector path')
    }
  }

  let total = 4
  for (const entry of normalized) total += 2 + entry.pathBytes.byteLength + 8 + HASH_BYTES
  const output = b4a.alloc(total)
  b4a.writeUInt32BE(output, normalized.length, 0)
  let offset = 4
  for (const entry of normalized) {
    writeU16BE(output, entry.pathBytes.byteLength, offset)
    offset += 2
    b4a.copy(entry.pathBytes, output, offset)
    offset += entry.pathBytes.byteLength
    b4a.copy(encodeU64(entry.vectorLength), output, offset)
    offset += 8
    b4a.copy(entry.vectorHash, output, offset)
    offset += HASH_BYTES
  }
  return output
}

export function decodeVectorManifest (input) {
  const bytes = asBuffer(input, 'vector manifest bytes')
  requireManifestBytes(bytes, 0, 4, 'entry count')
  const count = bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3]
  if (count === 0) protocolError('BAD_ENCODING', 'vector manifest cannot be empty')
  // Every row needs at least one path byte plus its fixed 42-byte framing. This
  // check rejects attacker-selected loop counts before iteration.
  if (count > Math.floor((bytes.byteLength - 4) / 43)) {
    protocolError('BAD_ENCODING', 'vector manifest entry count exceeds its bytes')
  }

  const entries = []
  let offset = 4
  let previousPathBytes = null
  for (let index = 0; index < count; index++) {
    requireManifestBytes(bytes, offset, 2, 'path length')
    const pathLength = bytes[offset] * 0x100 + bytes[offset + 1]
    offset += 2
    if (pathLength === 0) protocolError('BAD_ENCODING', 'vector path must be non-empty')
    requireManifestBytes(bytes, offset, pathLength + 8 + HASH_BYTES, 'entry')
    const pathBytes = b4a.from(bytes.subarray(offset, offset + pathLength))
    offset += pathLength
    const path = b4a.toString(pathBytes, 'utf8')
    const canonicalPathBytes = validateVectorPath(path)
    if (!b4a.equals(pathBytes, canonicalPathBytes)) {
      protocolError('BAD_ENCODING', 'vector path is not canonical UTF-8')
    }
    if (previousPathBytes && b4a.compare(previousPathBytes, pathBytes) >= 0) {
      protocolError('BAD_ENCODING', 'vector manifest paths must be strictly sorted')
    }
    previousPathBytes = pathBytes
    const vectorLength = readManifestU64(bytes, offset)
    offset += 8
    const vectorHash = b4a.from(bytes.subarray(offset, offset + HASH_BYTES))
    offset += HASH_BYTES
    entries.push(Object.freeze({ path, vectorLength, vectorHash }))
  }
  if (offset !== bytes.byteLength) protocolError('BAD_ENCODING', 'vector manifest has trailing bytes')
  return Object.freeze(entries)
}

export { HASH_BYTES, validateVectorPath }
