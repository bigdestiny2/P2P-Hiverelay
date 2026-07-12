import b4a from 'b4a'
import { FAMILY } from '@hiverelay/blind-protocol'
import {
  verifyBlindCellInboxControlSnapshotSemanticResult,
  verifyBlindCellInboxControlSnapshotSemanticVerifier,
  verifyBlindCellInboxControlSnapshotSemanticVerifierPartitionKey
} from './cell-inbox-control-snapshot.js'
import {
  verifyBlindCoreControlSnapshotSemanticResult,
  verifyBlindCoreControlSnapshotSemanticVerifier,
  verifyBlindCoreControlSnapshotSemanticVerifierPartitionKey
} from './core-control-snapshot.js'

const MAX_U64 = (1n << 64n) - 1n
const DEFAULT_MAXIMUM_BUFFERED_BYTES = 64 * 1024 * 1024
const MAXIMUM_BUFFERED_BYTES = 256 * 1024 * 1024
const BUFFERED_ENTRY_OVERHEAD = 128
const AUTHORITIES = new WeakMap()
const VERIFIERS = new WeakSet()
const EMPTY_GENESIS_VERIFIERS = new WeakSet()
const VERIFIED_RESULTS = new WeakMap()

const EMPTY_GENESIS_GLOBAL_ENTRIES = Object.freeze([
  Object.freeze({ entryKind: 6, key: Object.freeze([FAMILY.CELL, 1]) }),
  Object.freeze({ entryKind: 6, key: Object.freeze([FAMILY.INBOX, 1]) }),
  Object.freeze({ entryKind: 6, key: Object.freeze([FAMILY.CORE, 1]) })
])

export const BLIND_CELL_INBOX_CORE_CONTROL_SNAPSHOT_STATUS = Object.freeze({
  cellInboxCoreRetryCompositionImplemented: true,
  exactSharedCheckpointTupleVerified: true,
  exactSharedPartitionKeyVerified: true,
  coreOpenReplicationRetryLifecycleComplete: true,
  coreComplete: false,
  allFamilyCompositionImplemented: false,
  publicationAuthorized: false,
  emptyGenesisPublicationSemanticAuthorityImplemented: true,
  productionComplete: false,
  exclusions: Object.freeze([
    'CORE_MIRROR_BODY_STORAGE_AND_RECOVERY_UNIMPLEMENTED',
    'CORE_PROVE_BODY_AND_EVIDENCE_STORAGE_RECOVERY_UNIMPLEMENTED',
    'CORE_UPSTREAM_CHILD_AND_TICKET_RESTORE_FORBIDDEN',
    'CORE_STREAM_ENGINE_LIVE_TO_TERMINAL_RECOVERY_POLICY_UNIMPLEMENTED',
    'DESCRIPTOR_IDENTITY_FLOOR_SNAPSHOT_UNIMPLEMENTED',
    'CROSS_SERVICE_GLOBAL_SNAPSHOT_COMPOSITION_UNIMPLEMENTED',
    'INBOX_FRAME_BODY_AVAILABILITY_AND_HASH_VERIFICATION_UNIMPLEMENTED',
    'CELL_INBOX_CORE_WAL_STATE_MACHINE_AND_ENGINE_RESTORE_UNIMPLEMENTED',
    'SCALABLE_EXTERNAL_SORTED_CANDIDATE_STREAM_UNIMPLEMENTED',
    'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED'
  ])
})

export class BlindCellInboxCoreControlSnapshotIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindCellInboxCoreControlSnapshotIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function fail (message) {
  throw new BlindCellInboxCoreControlSnapshotIntegrityError(message)
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && value.every(byte => byte === 0)) fail(`${field} must be nonzero`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function tuple (header) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail('snapshot semantic header is required')
  return Object.freeze({
    relayPublicKey: b4a.from(bytes(header.relayPublicKey, 32, 'header relayPublicKey', true)),
    storeId: b4a.from(bytes(header.storeId, 32, 'header storeId', true)),
    durabilityContinuityHash: b4a.from(bytes(
      header.durabilityContinuityHash, 32, 'header durabilityContinuityHash', true)),
    walSequence: u64(header.walSequence, 'header walSequence'),
    walHash: b4a.from(bytes(header.walHash, 32, 'header walHash', true))
  })
}

function checkpointTuple (header, expected) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('checkpointHeader is required for Cell+Inbox+Core reconstruction')
  }
  const output = Object.freeze({
    relayPublicKey: b4a.from(bytes(header.relayPublicKey, 32, 'checkpoint relayPublicKey', true)),
    storeId: b4a.from(bytes(header.storeId, 32, 'checkpoint storeId', true)),
    durabilityContinuityHash: b4a.from(bytes(
      header.durabilityContinuityHash, 32, 'checkpoint durabilityContinuityHash', true)),
    coveredWalSequence: u64(header.coveredWalSequence, 'checkpoint coveredWalSequence'),
    coveredWalHash: b4a.from(bytes(header.coveredWalHash, 32, 'checkpoint coveredWalHash', true)),
    epochFloor: integer(header.epochFloor, 0, 0xffffffff, 'checkpoint epochFloor')
  })
  if (!b4a.equals(output.relayPublicKey, expected.relayPublicKey) ||
      !b4a.equals(output.storeId, expected.storeId) ||
      !b4a.equals(output.durabilityContinuityHash, expected.durabilityContinuityHash) ||
      output.coveredWalSequence !== expected.walSequence ||
      !b4a.equals(output.coveredWalHash, expected.walHash)) {
    fail('Cell+Inbox+Core semantic snapshot tuple does not match its checkpoint header')
  }
  return output
}

function copyEntry (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('snapshot entry must be an object')
  const entryKind = integer(input.entryKind, 1, 8, 'entryKind')
  const key = b4a.from(bytes(input.key, null, 'entry key'))
  const value = b4a.from(bytes(input.value, null, 'entry value'))
  if (key.byteLength < 2 || key.byteLength > 256 || value.byteLength > 0xffff) {
    fail('snapshot entry is outside its byte bounds')
  }
  if (key[0] !== FAMILY.CELL && key[0] !== FAMILY.INBOX && key[0] !== FAMILY.CORE) {
    fail('Cell+Inbox+Core composition rejects an uncovered control snapshot family')
  }
  return Object.freeze({ entryKind, key, value })
}

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

async function partitionEntries (input, maximumEntries, maximumBufferedBytes) {
  if (!input || (typeof input[Symbol.iterator] !== 'function' &&
      typeof input[Symbol.asyncIterator] !== 'function')) {
    fail('snapshot entries must be iterable')
  }
  const output = { cellInbox: [], core: [], count: 0, bufferedBytes: 0 }
  let previous = null
  for await (const raw of input) {
    if (++output.count > maximumEntries) fail('Cell+Inbox+Core snapshot exceeds its configured entry bound')
    const entry = copyEntry(raw)
    output.bufferedBytes += BUFFERED_ENTRY_OVERHEAD + entry.key.byteLength + entry.value.byteLength
    if (!Number.isSafeInteger(output.bufferedBytes) || output.bufferedBytes > maximumBufferedBytes) {
      fail('Cell+Inbox+Core snapshot exceeds its configured buffered-byte bound')
    }
    if (previous && compareEntries(previous, entry) >= 0) {
      fail('Cell+Inbox+Core snapshot entries are not strictly sorted and duplicate-free')
    }
    previous = entry
    if (entry.key[0] === FAMILY.CORE) output.core.push(entry)
    else output.cellInbox.push(entry)
  }
  if (output.cellInbox.length < 2 || output.core.length < 1) {
    fail('Cell+Inbox+Core composition requires all three covered recovery fragments')
  }
  return output
}

function authorityState (authority) {
  const state = AUTHORITIES.get(authority)
  if (!state) throw new TypeError('a branded Cell+Inbox+Core control snapshot semantic authority is required')
  return state
}

export function createBlindCellInboxCoreControlSnapshotSemanticAuthority (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Cell+Inbox+Core semantic authority options must be an object')
  }
  const cellInboxVerifier = verifyBlindCellInboxControlSnapshotSemanticVerifier(options.cellInboxVerifier)
  const coreVerifier = verifyBlindCoreControlSnapshotSemanticVerifier(options.coreVerifier)
  const partitionKey = b4a.from(bytes(options.partitionKey, 32, 'partitionKey', true))
  try {
    verifyBlindCellInboxControlSnapshotSemanticVerifierPartitionKey(cellInboxVerifier, partitionKey)
    verifyBlindCoreControlSnapshotSemanticVerifierPartitionKey(coreVerifier, partitionKey)
  } finally {
    partitionKey.fill(0)
  }
  const maximumEntries = options.maximumEntries == null
    ? 0x1000000
    : integer(options.maximumEntries, 3, 0x1000000, 'maximumEntries')
  const maximumBufferedBytes = options.maximumBufferedBytes == null
    ? DEFAULT_MAXIMUM_BUFFERED_BYTES
    : integer(options.maximumBufferedBytes, 384, MAXIMUM_BUFFERED_BYTES, 'maximumBufferedBytes')
  const authority = Object.freeze({
    kind: 'BLIND_CELL_INBOX_CORE_RETRY_CONTROL_SNAPSHOT_RECOVERY_SEMANTIC_AUTHORITY_V1',
    coreOpenReplicationRetryOnly: true,
    allFamilyComposition: false,
    publicationAuthorized: false,
    productionComplete: false
  })
  AUTHORITIES.set(authority, Object.freeze({
    cellInboxVerifier,
    coreVerifier,
    maximumEntries,
    maximumBufferedBytes
  }))
  return authority
}

export async function reconstructBlindCellInboxCoreControlSnapshot (authority, input = {}) {
  const state = authorityState(authority)
  const ownedTuple = tuple(input.header)
  const ownedCheckpointTuple = checkpointTuple(input.checkpointHeader, ownedTuple)
  const declaredEntryCount = integer(input.declaredEntryCount, 3, state.maximumEntries, 'declaredEntryCount')
  const partitioned = await partitionEntries(input.entries, state.maximumEntries, state.maximumBufferedBytes)
  if (partitioned.count !== declaredEntryCount) {
    fail('Cell+Inbox+Core semantic entry count does not match the declared snapshot count')
  }
  const childInput = entries => Object.freeze({
    header: ownedTuple,
    checkpointHeader: ownedCheckpointTuple,
    declaredEntryCount: entries.length,
    entries
  })
  const cellInboxResult = await state.cellInboxVerifier(childInput(partitioned.cellInbox))
  const coreResult = await state.coreVerifier(childInput(partitioned.core))
  const expected = { ...ownedTuple }
  verifyBlindCellInboxControlSnapshotSemanticResult(cellInboxResult, {
    ...expected,
    entryCount: partitioned.cellInbox.length
  })
  verifyBlindCoreControlSnapshotSemanticResult(coreResult, {
    ...expected,
    entryCount: partitioned.core.length
  })
  if (cellInboxResult.cellInboxComplete !== true || coreResult.coreOpenReplicationRetryComplete !== true ||
      coreResult.coreComplete !== false || cellInboxResult.allFamilyComplete !== false ||
      cellInboxResult.publicationAuthorized !== false || coreResult.publicationAuthorized !== false ||
      cellInboxResult.productionComplete !== false || coreResult.productionComplete !== false) {
    fail('covered semantic results are not the required recovery-only fragments')
  }

  const verified = Object.freeze({
    ...ownedTuple,
    entryCount: partitioned.count,
    cellInboxEntryCount: partitioned.cellInbox.length,
    coreEntryCount: partitioned.core.length,
    cellInboxResult,
    coreResult
  })
  const result = {}
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    Object.defineProperty(result, field, { enumerable: true, get: () => b4a.from(verified[field]) })
  }
  Object.defineProperty(result, 'cellState', { enumerable: true, get: () => verified.cellInboxResult.cellState })
  Object.defineProperty(result, 'inboxState', { enumerable: true, get: () => verified.cellInboxResult.inboxState })
  Object.defineProperty(result, 'coreState', { enumerable: true, get: () => verified.coreResult.coreState })
  for (const [field, value] of Object.entries({
    walSequence: verified.walSequence,
    entryCount: verified.entryCount,
    cellInboxEntryCount: verified.cellInboxEntryCount,
    coreEntryCount: verified.coreEntryCount,
    cellComplete: true,
    inboxComplete: true,
    cellInboxComplete: true,
    coreOpenReplicationRetryComplete: true,
    coreComplete: false,
    cellInboxCoreRetryComplete: true,
    allFamilyComplete: false,
    recoveryVerified: true,
    publicationAuthorized: false,
    productionComplete: false,
    exclusions: BLIND_CELL_INBOX_CORE_CONTROL_SNAPSHOT_STATUS.exclusions
  })) Object.defineProperty(result, field, { enumerable: true, value })
  Object.freeze(result)
  VERIFIED_RESULTS.set(result, verified)
  return result
}

export function createBlindCellInboxCoreControlSnapshotSemanticVerifier (authority) {
  authorityState(authority)
  const verifier = input => reconstructBlindCellInboxCoreControlSnapshot(authority, input)
  VERIFIERS.add(verifier)
  return verifier
}

// Genesis is the only publication path that may safely use the otherwise
// recovery-only Cell+Inbox+Core reconstruction today. Its authority is kept
// distinct and deliberately narrow: exactly one canonical empty global fragment
// for each covered family, and no application/control records of any kind.
export function createBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier (authority) {
  authorityState(authority)
  const verifier = async input => {
    if (!input || typeof input !== 'object' || Array.isArray(input) || input.declaredEntryCount !== 3) {
      fail('empty genesis requires exactly three declared control snapshot entries')
    }
    const observed = []
    for await (const raw of input.entries) {
      if (observed.length >= EMPTY_GENESIS_GLOBAL_ENTRIES.length) {
        fail('empty genesis contains more than three control snapshot entries')
      }
      observed.push(copyEntry(raw))
    }
    if (observed.length !== EMPTY_GENESIS_GLOBAL_ENTRIES.length) {
      fail('empty genesis is missing a canonical family-global fragment')
    }
    for (let index = 0; index < EMPTY_GENESIS_GLOBAL_ENTRIES.length; index++) {
      const expected = EMPTY_GENESIS_GLOBAL_ENTRIES[index]
      const entry = observed[index]
      if (entry.entryKind !== expected.entryKind ||
          !b4a.equals(entry.key, b4a.from(expected.key))) {
        fail('empty genesis contains a non-global or noncanonical family fragment')
      }
    }
    const result = await reconstructBlindCellInboxCoreControlSnapshot(authority, {
      ...input,
      declaredEntryCount: observed.length,
      entries: observed
    })
    verifyBlindCellInboxCoreControlSnapshotSemanticResult(result, { entryCount: 3 })
    return result
  }
  VERIFIERS.add(verifier)
  EMPTY_GENESIS_VERIFIERS.add(verifier)
  return verifier
}

export function verifyBlindCellInboxCoreControlSnapshotSemanticVerifier (verifier) {
  if (!VERIFIERS.has(verifier)) {
    throw new TypeError('a branded Cell+Inbox+Core control snapshot semantic verifier is required')
  }
  return verifier
}

export function verifyBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier (verifier) {
  verifyBlindCellInboxCoreControlSnapshotSemanticVerifier(verifier)
  if (!EMPTY_GENESIS_VERIFIERS.has(verifier)) {
    throw new TypeError('a branded empty-genesis Cell+Inbox+Core semantic verifier is required')
  }
  return verifier
}

export function verifyBlindCellInboxCoreControlSnapshotSemanticResult (result, expected = {}) {
  const verified = VERIFIED_RESULTS.get(result)
  if (!verified) throw new TypeError('a branded Cell+Inbox+Core control snapshot semantic result is required')
  for (const field of ['entryCount', 'cellInboxEntryCount', 'coreEntryCount']) {
    if (expected[field] != null && integer(expected[field], 1, 0x1000000, `expected ${field}`) !== verified[field]) {
      fail(`Cell+Inbox+Core semantic result ${field} does not match`)
    }
  }
  if (expected.walSequence != null && u64(expected.walSequence, 'expected walSequence') !== verified.walSequence) {
    fail('Cell+Inbox+Core semantic result walSequence does not match')
  }
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !b4a.equals(bytes(expected[field], 32, `expected ${field}`), verified[field])) {
      fail(`Cell+Inbox+Core semantic result ${field} does not match`)
    }
  }
  verifyBlindCellInboxControlSnapshotSemanticResult(verified.cellInboxResult, {
    ...verified,
    entryCount: verified.cellInboxEntryCount
  })
  verifyBlindCoreControlSnapshotSemanticResult(verified.coreResult, {
    ...verified,
    entryCount: verified.coreEntryCount
  })
  if (result.cellInboxCoreRetryComplete !== true || result.coreComplete !== false ||
      result.allFamilyComplete !== false || result.recoveryVerified !== true ||
      result.publicationAuthorized !== false || result.productionComplete !== false) {
    fail('Cell+Inbox+Core semantic result must remain partial and recovery-only')
  }
  return result
}
