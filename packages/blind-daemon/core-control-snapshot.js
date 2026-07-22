import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE,
  FAMILY,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindCoreControlGlobalSnapshotV1,
  blindCoreOpenReplicationRetrySnapshotV1,
  coreOpenReplicationRequestCommitment,
  coreOpenReplicationResultV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { coreOpenReplicationLogicalRetryKey } from './core-stream.js'
import { deriveBlindVirtualBucket } from './virtual-bucket.js'

const MAX_U64 = (1n << 64n) - 1n
const AUTHORITIES = new WeakMap()
const VERIFIERS = new WeakMap()
const VERIFIED_RESULTS = new WeakMap()

const ENTRY_KIND = Object.freeze({
  CORE_RETRY: 5,
  CORE_GLOBAL: 6
})

const SUBTYPE = Object.freeze({
  OPEN_REPLICATION_RETRY: 1,
  GLOBAL: 1
})

const STATE_TO_LIFECYCLE = Object.freeze({
  RESERVED: BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.RESERVED,
  LIVE: BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE,
  TERMINAL: BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL
})

const LIFECYCLE_TO_STATE = Object.freeze({
  [BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.RESERVED]: 'RESERVED',
  [BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE]: 'LIVE',
  [BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL]: 'TERMINAL'
})

export const BLIND_CORE_CONTROL_SNAPSHOT_KEYSPACE = Object.freeze({
  familyPrefix: FAMILY.CORE,
  entryKind: ENTRY_KIND,
  subtype: SUBTYPE,
  keyFormat: 'family:u8 || subtype:u8 || logicalRetryKey:32',
  globalKey: Object.freeze([FAMILY.CORE, SUBTYPE.GLOBAL])
})

export const BLIND_CORE_CONTROL_SNAPSHOT_STATUS = Object.freeze({
  recoverySemanticAuthorityImplemented: true,
  coreOpenReplicationRetryLifecycleComplete: true,
  exactSpendLogicalChannelIndexesReconstructed: true,
  privatePartitionBucketMappingVerified: true,
  signedResultBindingVerified: true,
  coreMirrorBodyStorageImplemented: false,
  coreProveBodyStorageImplemented: false,
  coreReplicationEngineRestoreImplemented: false,
  scalableCandidateEntryStreamingImplemented: false,
  publicationAuthorized: false,
  productionComplete: false,
  exclusions: Object.freeze([
    'CORE_MIRROR_BODY_STORAGE_AND_RECOVERY_UNIMPLEMENTED',
    'CORE_PROVE_BODY_AND_EVIDENCE_STORAGE_RECOVERY_UNIMPLEMENTED',
    'CORE_UPSTREAM_CHILD_AND_TICKET_RESTORE_FORBIDDEN',
    'CORE_STREAM_ENGINE_LIVE_TO_TERMINAL_RECOVERY_POLICY_UNIMPLEMENTED',
    'DESCRIPTOR_IDENTITY_FLOOR_SNAPSHOT_UNIMPLEMENTED',
    'CROSS_SERVICE_GLOBAL_SNAPSHOT_COMPOSITION_UNIMPLEMENTED',
    'SCALABLE_EXTERNAL_SORTED_CANDIDATE_STREAM_UNIMPLEMENTED',
    'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED'
  ])
})

export class BlindCoreControlSnapshotIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindCoreControlSnapshotIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function fail (message) {
  throw new BlindCoreControlSnapshotIntegrityError(message)
}

function bytes (value, minimum, maximum, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength < minimum || value.byteLength > maximum) {
    fail(`${field} must be ${minimum}..${maximum} bytes`)
  }
  if (nonzero && value.every(byte => byte === 0)) fail(`${field} must be nonzero`)
  return value
}

function bytes32 (value, field, nonzero = true) {
  return bytes(value, 32, 32, field, nonzero)
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    fail(`${field} is outside u64`)
  }
  return value
}

function safeNumber (value, field) {
  value = u64(value, field)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${field} exceeds the JavaScript safe-integer bound`)
  return Number(value)
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function hex (value) {
  return b4a.toString(value, 'hex')
}

function cloneValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (typeof value.byteLength === 'number') return b4a.from(value)
  if (value instanceof Map) {
    return new Map([...value].map(([key, child]) => [key, cloneValue(child)]))
  }
  if (Array.isArray(value)) return value.map(cloneValue)
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneValue(child)]))
}

function requireMap (value, field) {
  if (!(value instanceof Map)) fail(`${field} must be a Map`)
  return value
}

function decodeValue (codec, value, field) {
  value = bytes(value, 0, 0xffff, `${field} bytes`)
  let decoded
  try {
    decoded = decodeCanonical(codec, value, { copyBytes: true })
  } catch (error) {
    fail(`${field} is not canonical: ${error.message}`)
  }
  if (!b4a.equals(encodeCanonical(codec, decoded), value)) {
    fail(`${field} canonical bytes changed on re-encoding`)
  }
  return decoded
}

function normalizeResult (value) {
  if (value == null) return null
  if (typeof value.byteLength === 'number') {
    return decodeValue(coreOpenReplicationResultV1, value, 'Core open result')
  }
  try {
    return decodeCanonical(coreOpenReplicationResultV1,
      encodeCanonical(coreOpenReplicationResultV1, value), { copyBytes: true })
  } catch (error) {
    fail(`Core open result is not canonical: ${error.message}`)
  }
}

function lifecycleState (value) {
  const state = value && typeof value.state === 'string'
    ? value.state
    : value && typeof value.status === 'string'
      ? value.status.toUpperCase()
      : null
  const lifecycle = STATE_TO_LIFECYCLE[state]
  if (lifecycle == null) fail('Core retry record state must be RESERVED, LIVE, or TERMINAL')
  return lifecycle
}

function channelKey (parentSessionId, controlChannelId) {
  return `${hex(parentSessionId)}:${controlChannelId}`
}

function entryKey (subtype, identity = null) {
  return identity == null
    ? b4a.from([FAMILY.CORE, subtype])
    : b4a.concat([b4a.from([FAMILY.CORE, subtype]), identity])
}

function encodedEntry (entryKind, subtype, identity, codec, value) {
  const key = entryKey(subtype, identity)
  const encoded = encodeCanonical(codec, value)
  if (key.byteLength > 256 || encoded.byteLength > 0xffff) {
    fail('Core snapshot entry exceeds the control snapshot bounds')
  }
  return Object.freeze({ entryKind, key, value: encoded })
}

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

function persistentRecordValue (record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail('Core retry record must be an object')
  }
  if (record.family != null && record.family !== FAMILY.CORE) fail('Core retry record has the wrong family')
  if (record.operation != null && record.operation !== 'OPEN_REPLICATION') {
    fail('Core retry record has the wrong operation')
  }
  const logicalRetryKey = b4a.from(bytes32(record.logicalRetryKey, 'logicalRetryKey'))
  const derivedBucket = deriveBlindVirtualBucket(FAMILY.CORE, logicalRetryKey)
  if (record.recordVirtualBucket != null &&
      integer(record.recordVirtualBucket, 0, 0xffff, 'recordVirtualBucket') !== derivedBucket) {
    fail('Core retry record virtual bucket does not match the public deterministic mapping')
  }
  const lifecycle = lifecycleState(record)
  const terminal = lifecycle === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL
  if (terminal && record.terminalReason == null) fail('terminal Core retry record requires a terminal reason')
  const terminalReason = terminal
    ? b4a.from(String(record.terminalReason), 'utf8')
    : null
  if (!terminal && record.terminalReason != null) fail('non-terminal Core retry record carries a terminal reason')
  return {
    version: 1,
    lifecycleState: lifecycle,
    logicalRetryKey,
    spendTag: b4a.from(bytes(record.spendTag, 1, 128, 'spendTag', true)),
    requestCommitment: b4a.from(bytes32(record.requestCommitment, 'requestCommitment')),
    wireProfileHash: b4a.from(bytes32(record.wireProfileHash, 'wireProfileHash')),
    sessionClass: integer(record.sessionClass, 1, 3, 'sessionClass'),
    clientNonce: b4a.from(bytes32(record.clientNonce, 'clientNonce', false)),
    parentSessionId: b4a.from(bytes(record.parentSessionId, 1, 256, 'parentSessionId', true)),
    controlChannelId: u64(record.controlChannelId, 'controlChannelId', true),
    parentChannelBinding: b4a.from(bytes32(record.parentChannelBinding, 'parentChannelBinding')),
    streamId: u64(record.streamId, 'streamId', true),
    maxSessionBytes: u64(record.maxSessionBytes, 'maxSessionBytes', true),
    idleMillis: integer(record.idleMillis, 1, 0xffffffff, 'idleMillis'),
    lifetimeMillis: integer(record.lifetimeMillis, 1, 0xffffffff, 'lifetimeMillis'),
    openedAtEpoch: integer(record.openedAtEpoch, 0, 0xffffffff, 'openedAtEpoch'),
    recordVirtualBucket: derivedBucket,
    resultBytes: record.result == null
      ? null
      : encodeCanonical(coreOpenReplicationResultV1, normalizeResult(record.result)),
    terminalReason
  }
}

function candidateEntries (state, maximumCandidateEntries) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('Core snapshot state must be an object')
  bytes32(state.relayPublicKey, 'relayPublicKey')
  const recordsByLogical = requireMap(state.recordsByLogical, 'recordsByLogical')
  const recordsBySpend = requireMap(state.recordsBySpend, 'recordsBySpend')
  const controlChannels = requireMap(state.controlChannels, 'controlChannels')
  const epochFloor = integer(state.epochFloor, 0, 0xffffffff, 'epochFloor')
  if (typeof state.clockUnsafe !== 'boolean') fail('clockUnsafe must be a boolean')
  if (state.readOnlyReason != null) {
    fail('Core retry snapshot has no integrity-evidence schema for a read-only recovery gap')
  }
  if (recordsByLogical.size + 1 > maximumCandidateEntries) {
    fail('Core candidate snapshot exceeds its configured entry bound')
  }

  const output = []
  const stateCounts = { reserved: 0, live: 0, terminal: 0, results: 0, bytes: 0 }
  for (const [mapKey, record] of recordsByLogical) {
    const value = persistentRecordValue(record)
    if (typeof mapKey !== 'string' || mapKey !== hex(value.logicalRetryKey)) {
      fail('Core logical index key does not match logicalRetryKey')
    }
    const entry = encodedEntry(ENTRY_KIND.CORE_RETRY, SUBTYPE.OPEN_REPLICATION_RETRY,
      value.logicalRetryKey, blindCoreOpenReplicationRetrySnapshotV1, value)
    output.push(entry)
    stateCounts.bytes += entry.value.byteLength
    if (value.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.RESERVED) stateCounts.reserved++
    if (value.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE) stateCounts.live++
    if (value.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL) stateCounts.terminal++
    if (value.resultBytes != null) stateCounts.results++
  }
  output.sort(compareEntries)
  output.push(encodedEntry(ENTRY_KIND.CORE_GLOBAL, SUBTYPE.GLOBAL, null,
    blindCoreControlGlobalSnapshotV1, {
      version: 1,
      epochFloor,
      clockUnsafe: state.clockUnsafe ? 1 : 0,
      recordCount: BigInt(recordsByLogical.size),
      reservedCount: BigInt(stateCounts.reserved),
      liveCount: BigInt(stateCounts.live),
      terminalCount: BigInt(stateCounts.terminal),
      spendIndexCount: BigInt(recordsBySpend.size),
      logicalIndexCount: BigInt(recordsByLogical.size),
      channelIndexCount: BigInt(controlChannels.size),
      resultCount: BigInt(stateCounts.results),
      snapshotRecordBytes: BigInt(stateCounts.bytes)
    }))
  return output
}

function copyEntry (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('Core snapshot entry must be an object')
  const entryKind = integer(input.entryKind, 1, 8, 'entryKind')
  const key = b4a.from(bytes(input.key, 1, 256, 'entry key'))
  const value = b4a.from(bytes(input.value, 0, 0xffff, 'entry value'))
  if (key.byteLength < 2 || key[0] !== FAMILY.CORE) fail('Core reconstruction rejects non-Core snapshot entries')
  return { entryKind, key, value }
}

function entryIdentity (entry, expectedKind, expectedSubtype, expectedBytes, field) {
  if (entry.entryKind !== expectedKind || entry.key[1] !== expectedSubtype ||
      entry.key.byteLength !== 2 + expectedBytes) {
    fail(`${field} has an invalid kind, subtype, or key length`)
  }
  return entry.key.subarray(2)
}

function same (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function verifyResultBinding (value, result, relayPublicKey, storeId, durabilityContinuityHash) {
  if (result == null) return
  const binding = result.relayBinding
  if (!same(binding.relayPublicKey, relayPublicKey) || !same(binding.storeId, storeId) ||
      !same(binding.durabilityContinuityHash, durabilityContinuityHash) ||
      !same(result.wireProfileHash, value.wireProfileHash) || result.sessionClass !== value.sessionClass ||
      result.controlChannelId !== value.controlChannelId ||
      !same(result.parentChannelBinding, value.parentChannelBinding) || result.streamId !== value.streamId ||
      result.maxSessionBytes !== value.maxSessionBytes || result.idleMillis !== value.idleMillis ||
      result.lifetimeMillis !== value.lifetimeMillis || result.openedAtEpoch !== value.openedAtEpoch ||
      !same(result.requestNonce, value.clientNonce) ||
      !same(result.requestCommitment, value.requestCommitment)) {
    fail('Core signed result does not match its retained request, channel, stream, or checkpoint binding')
  }
  const canonical = encodeCanonical(coreOpenReplicationResultV1, result)
  const unsigned = canonical.subarray(0, canonical.byteLength - 64)
  const payload = resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT, unsigned)
  if (!sodium.crypto_sign_verify_detached(result.signature, payload, relayPublicKey)) {
    fail('Core retained open result signature is invalid')
  }
}

function addRecord (state, value, context) {
  const logicalRetryKey = b4a.from(value.logicalRetryKey)
  const logicalKey = hex(logicalRetryKey)
  if (state.recordsByLogical.has(logicalKey)) fail('Core snapshot redefines a logical retry record')
  const expectedLogical = coreOpenReplicationLogicalRetryKey(context.relayPublicKey, {
    wireProfileHash: value.wireProfileHash,
    sessionClass: value.sessionClass,
    clientNonce: value.clientNonce
  })
  if (!same(expectedLogical, logicalRetryKey)) fail('Core logical retry key does not match its request fields')
  const expectedRequest = coreOpenReplicationRequestCommitment({
    relayPublicKey: context.relayPublicKey,
    wireProfileHash: value.wireProfileHash,
    sessionClass: value.sessionClass,
    controlChannelId: value.controlChannelId,
    parentChannelBinding: value.parentChannelBinding,
    clientNonce: value.clientNonce
  })
  if (!same(expectedRequest, value.requestCommitment)) {
    fail('Core request commitment does not match its retained open fields')
  }
  if (value.recordVirtualBucket !== deriveBlindVirtualBucket(FAMILY.CORE, logicalRetryKey)) {
    fail('Core retry record virtual bucket does not match the public deterministic mapping')
  }
  if (value.openedAtEpoch > context.epochFloor) fail('Core retry openedAtEpoch exceeds the checkpoint floor')
  const result = value.resultBytes == null
    ? null
    : decodeValue(coreOpenReplicationResultV1, value.resultBytes, 'Core retained open result')
  verifyResultBinding(value, result, context.relayPublicKey, context.storeId, context.durabilityContinuityHash)

  const spendKey = hex(value.spendTag)
  const authenticatedChannel = channelKey(value.parentSessionId, value.controlChannelId)
  const streamKey = value.streamId.toString()
  const requestKey = hex(value.requestCommitment)
  if (state.recordsBySpend.has(spendKey)) fail('Core snapshot repeats an admission spend tag')
  if (state.controlChannels.has(authenticatedChannel)) {
    fail('Core snapshot repeats an authenticated parent/control channel')
  }
  if (state.recordsByStream.has(streamKey)) fail('Core snapshot repeats a streamId')
  if (state.recordsByRequest.has(requestKey)) fail('Core snapshot repeats a request commitment')

  const record = {
    family: FAMILY.CORE,
    operation: 'OPEN_REPLICATION',
    state: LIFECYCLE_TO_STATE[value.lifecycleState],
    lifecycleState: value.lifecycleState,
    logicalRetryKey,
    spendTag: b4a.from(value.spendTag),
    requestCommitment: b4a.from(value.requestCommitment),
    wireProfileHash: b4a.from(value.wireProfileHash),
    sessionClass: value.sessionClass,
    clientNonce: b4a.from(value.clientNonce),
    parentSessionId: b4a.from(value.parentSessionId),
    controlChannelId: value.controlChannelId,
    parentChannelBinding: b4a.from(value.parentChannelBinding),
    streamId: value.streamId,
    maxSessionBytes: value.maxSessionBytes,
    idleMillis: value.idleMillis,
    lifetimeMillis: value.lifetimeMillis,
    openedAtEpoch: value.openedAtEpoch,
    recordVirtualBucket: value.recordVirtualBucket,
    result: cloneValue(result),
    terminalReason: value.terminalReason == null ? null : b4a.toString(value.terminalReason, 'ascii')
  }
  state.recordsByLogical.set(logicalKey, record)
  state.recordsBySpend.set(spendKey, record)
  state.controlChannels.set(authenticatedChannel, record)
  state.recordsByStream.set(streamKey, record)
  state.recordsByRequest.set(requestKey, record)
}

async function reconstructEntries (input, context) {
  if (!input || (typeof input[Symbol.iterator] !== 'function' &&
      typeof input[Symbol.asyncIterator] !== 'function')) {
    fail('Core snapshot entries must be iterable')
  }
  const state = {
    recordsByLogical: new Map(),
    recordsBySpend: new Map(),
    controlChannels: new Map(),
    recordsByStream: new Map(),
    recordsByRequest: new Map()
  }
  let previous = null
  let count = 0
  let global = null
  let snapshotRecordBytes = 0
  for await (const raw of input) {
    if (++count > context.maximumCandidateEntries) fail('Core snapshot exceeds its configured entry bound')
    const entry = copyEntry(raw)
    if (previous && compareEntries(previous, entry) >= 0) {
      fail('Core snapshot entries are not strictly sorted and duplicate-free')
    }
    previous = entry
    if (entry.entryKind === ENTRY_KIND.CORE_RETRY && entry.key[1] === SUBTYPE.OPEN_REPLICATION_RETRY) {
      const identity = entryIdentity(entry, ENTRY_KIND.CORE_RETRY,
        SUBTYPE.OPEN_REPLICATION_RETRY, 32, 'Core retry record')
      const value = decodeValue(blindCoreOpenReplicationRetrySnapshotV1, entry.value, 'Core retry record')
      if (!same(identity, value.logicalRetryKey)) fail('Core retry key does not match logicalRetryKey')
      snapshotRecordBytes += entry.value.byteLength
      addRecord(state, value, context)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CORE_GLOBAL && entry.key[1] === SUBTYPE.GLOBAL) {
      entryIdentity(entry, ENTRY_KIND.CORE_GLOBAL, SUBTYPE.GLOBAL, 0, 'Core global record')
      if (global != null) fail('Core snapshot contains more than one global record')
      global = decodeValue(blindCoreControlGlobalSnapshotV1, entry.value, 'Core global record')
      continue
    }
    fail(`unknown Core control snapshot entry kind/subtype ${entry.entryKind}/${entry.key[1]}`)
  }
  if (context.declaredEntryCount != null && count !== context.declaredEntryCount) {
    fail('Core semantic entry count does not match the declared snapshot count')
  }
  if (global == null) fail('Core snapshot is incomplete without its global record')
  if (global.epochFloor !== context.epochFloor) fail('Core epoch floor does not match the checkpoint header')

  const records = [...state.recordsByLogical.values()]
  const expected = {
    recordCount: records.length,
    reservedCount: records.filter(record => record.state === 'RESERVED').length,
    liveCount: records.filter(record => record.state === 'LIVE').length,
    terminalCount: records.filter(record => record.state === 'TERMINAL').length,
    spendIndexCount: state.recordsBySpend.size,
    logicalIndexCount: state.recordsByLogical.size,
    channelIndexCount: state.controlChannels.size,
    resultCount: records.filter(record => record.result != null).length,
    snapshotRecordBytes
  }
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (safeNumber(global[field], field) !== expectedValue) {
      fail(`Core global ${field} does not match reconstructed state`)
    }
  }
  if (expected.recordCount !== expected.reservedCount + expected.liveCount + expected.terminalCount) {
    fail('Core lifecycle counts do not partition the retry records')
  }
  state.epochFloor = global.epochFloor
  state.clockUnsafe = global.clockUnsafe === 1
  state.readOnlyReason = null
  delete state.recordsByStream
  delete state.recordsByRequest
  return { state, count }
}

function referencedLogicalKey (value, field) {
  if (typeof value === 'string') return value
  if (!value || typeof value !== 'object') fail(`${field} index value must identify a Core retry record`)
  if (typeof value.logicalKey === 'string') return value.logicalKey
  if (value.logicalRetryKey != null) return hex(bytes32(value.logicalRetryKey, `${field} logicalRetryKey`))
  fail(`${field} index value does not identify a logical retry key`)
}

function assertDerivedIndex (supplied, reconstructed, field) {
  supplied = requireMap(supplied, field)
  if (supplied.size !== reconstructed.size) fail(`Core ${field} count does not match reconstructed records`)
  for (const [key, value] of supplied) {
    const expected = reconstructed.get(key)
    if (!expected || referencedLogicalKey(value, field) !== hex(expected.logicalRetryKey)) {
      fail(`Core ${field} does not match reconstructed records`)
    }
  }
}

function authorityState (authority) {
  const state = AUTHORITIES.get(authority)
  if (!state) throw new TypeError('a branded Core control snapshot semantic authority is required')
  return state
}

function ownedTuple (header) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail('snapshot semantic header is required')
  return Object.freeze({
    relayPublicKey: b4a.from(bytes32(header.relayPublicKey, 'header relayPublicKey')),
    storeId: b4a.from(bytes32(header.storeId, 'header storeId')),
    durabilityContinuityHash: b4a.from(bytes32(
      header.durabilityContinuityHash, 'header durabilityContinuityHash')),
    walSequence: u64(header.walSequence, 'header walSequence', true),
    walHash: b4a.from(bytes32(header.walHash, 'header walHash'))
  })
}

function checkpointTuple (header, expected) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('checkpointHeader is required for Core reconstruction')
  }
  const value = Object.freeze({
    relayPublicKey: b4a.from(bytes32(header.relayPublicKey, 'checkpoint relayPublicKey')),
    storeId: b4a.from(bytes32(header.storeId, 'checkpoint storeId')),
    durabilityContinuityHash: b4a.from(bytes32(
      header.durabilityContinuityHash, 'checkpoint durabilityContinuityHash')),
    coveredWalSequence: u64(header.coveredWalSequence, 'checkpoint coveredWalSequence', true),
    coveredWalHash: b4a.from(bytes32(header.coveredWalHash, 'checkpoint coveredWalHash')),
    epochFloor: integer(header.epochFloor, 0, 0xffffffff, 'checkpoint epochFloor')
  })
  if (!same(value.relayPublicKey, expected.relayPublicKey) || !same(value.storeId, expected.storeId) ||
      !same(value.durabilityContinuityHash, expected.durabilityContinuityHash) ||
      value.coveredWalSequence !== expected.walSequence || !same(value.coveredWalHash, expected.walHash)) {
    fail('Core semantic snapshot tuple does not match its checkpoint header')
  }
  return value
}

export function createBlindCoreControlSnapshotSemanticAuthority (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Core semantic authority options must be an object')
  }
  const maximumCandidateEntries = options.maximumCandidateEntries == null
    ? 4097
    : integer(options.maximumCandidateEntries, 1, 0x1000000, 'maximumCandidateEntries')
  const authority = Object.freeze({
    kind: 'BLIND_CORE_CONTROL_SNAPSHOT_RECOVERY_SEMANTIC_AUTHORITY_V1',
    coreOpenReplicationRetryOnly: true,
    coreComplete: false,
    publicationAuthorized: false,
    productionComplete: false
  })
  AUTHORITIES.set(authority, Object.freeze({ maximumCandidateEntries }))
  return authority
}

export async function * streamBlindCoreControlSnapshotEntries (authority, engineState) {
  const state = authorityState(authority)
  const entries = candidateEntries(engineState, state.maximumCandidateEntries)
  const reconstructed = await reconstructEntries(entries, {
    relayPublicKey: bytes32(engineState.relayPublicKey, 'relayPublicKey'),
    storeId: bytes32(engineState.storeId, 'storeId'),
    durabilityContinuityHash: bytes32(engineState.durabilityContinuityHash, 'durabilityContinuityHash'),
    epochFloor: engineState.epochFloor,
    maximumCandidateEntries: state.maximumCandidateEntries,
    declaredEntryCount: entries.length
  })
  assertDerivedIndex(engineState.recordsBySpend, reconstructed.state.recordsBySpend, 'recordsBySpend')
  assertDerivedIndex(engineState.controlChannels, reconstructed.state.controlChannels, 'controlChannels')
  for (const entry of entries) yield entry
}

export async function reconstructBlindCoreControlSnapshot (authority, input = {}) {
  const state = authorityState(authority)
  const tuple = ownedTuple(input.header)
  const checkpoint = checkpointTuple(input.checkpointHeader, tuple)
  const declaredEntryCount = integer(input.declaredEntryCount, 1,
    state.maximumCandidateEntries, 'declaredEntryCount')
  const reconstructed = await reconstructEntries(input.entries, {
    relayPublicKey: tuple.relayPublicKey,
    storeId: tuple.storeId,
    durabilityContinuityHash: tuple.durabilityContinuityHash,
    epochFloor: checkpoint.epochFloor,
    maximumCandidateEntries: state.maximumCandidateEntries,
    declaredEntryCount
  })
  const verified = Object.freeze({
    ...tuple,
    entryCount: reconstructed.count,
    coreState: reconstructed.state
  })
  const result = {}
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    Object.defineProperty(result, field, { enumerable: true, get: () => b4a.from(verified[field]) })
  }
  Object.defineProperty(result, 'coreState', {
    enumerable: true,
    get: () => cloneValue(verified.coreState)
  })
  for (const [field, value] of Object.entries({
    walSequence: verified.walSequence,
    entryCount: verified.entryCount,
    coreOpenReplicationRetryComplete: true,
    coreComplete: false,
    recoveryVerified: true,
    publicationAuthorized: false,
    productionComplete: false,
    exclusions: BLIND_CORE_CONTROL_SNAPSHOT_STATUS.exclusions
  })) Object.defineProperty(result, field, { enumerable: true, value })
  Object.freeze(result)
  VERIFIED_RESULTS.set(result, verified)
  return result
}

export function createBlindCoreControlSnapshotSemanticVerifier (authority) {
  const state = authorityState(authority)
  const verifier = input => reconstructBlindCoreControlSnapshot(authority, input)
  VERIFIERS.set(verifier, state)
  return verifier
}

export function verifyBlindCoreControlSnapshotSemanticVerifier (verifier) {
  if (!VERIFIERS.has(verifier)) throw new TypeError('a branded Core control snapshot semantic verifier is required')
  return verifier
}

export function verifyBlindCoreControlSnapshotSemanticResult (result, expected = {}) {
  const verified = VERIFIED_RESULTS.get(result)
  if (!verified) throw new TypeError('a branded Core control snapshot semantic result is required')
  if (expected.entryCount != null && verified.entryCount !== expected.entryCount) {
    fail('Core semantic result entryCount does not match')
  }
  if (expected.walSequence != null && verified.walSequence !== u64(expected.walSequence, 'expected walSequence')) {
    fail('Core semantic result walSequence does not match')
  }
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !same(verified[field], bytes32(expected[field], `expected ${field}`))) {
      fail(`Core semantic result ${field} does not match`)
    }
  }
  if (result.coreOpenReplicationRetryComplete !== true || result.coreComplete !== false ||
      result.recoveryVerified !== true || result.publicationAuthorized !== false ||
      result.productionComplete !== false) {
    fail('Core semantic result must remain retry-only and recovery-only')
  }
  return result
}
