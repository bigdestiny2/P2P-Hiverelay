import b4a from 'b4a'
import { FAMILY } from '@hiverelay/blind-protocol'
import {
  verifyBlindCellControlSnapshotSemanticResult,
  verifyBlindCellControlSnapshotSemanticVerifier
} from './cell-control-snapshot.js'
import {
  verifyBlindInboxControlSnapshotSemanticResult,
  verifyBlindInboxControlSnapshotSemanticVerifier
} from './inbox-control-snapshot.js'

const MAX_U64 = (1n << 64n) - 1n
const DEFAULT_MAXIMUM_BUFFERED_BYTES = 64 * 1024 * 1024
const MAXIMUM_BUFFERED_BYTES = 256 * 1024 * 1024
// Arrays, object headers and allocator metadata cost substantially more than
// the key/value payload alone. Charge a conservative fixed amount so millions
// of tiny entries cannot bypass the byte bound and exhaust the process heap.
const BUFFERED_ENTRY_OVERHEAD = 128
const AUTHORITIES = new WeakMap()
const VERIFIERS = new WeakMap()
const VERIFIED_RESULTS = new WeakMap()

export const BLIND_CELL_INBOX_CONTROL_SNAPSHOT_STATUS = Object.freeze({
  cellInboxCompositionImplemented: true,
  singlePassFamilyPartitionImplemented: true,
  exactSharedCheckpointTupleVerified: true,
  allFamilyCompositionImplemented: false,
  publicationAuthorized: false,
  productionComplete: false,
  exclusions: Object.freeze([
    'CORE_CONTROL_SNAPSHOT_UNIMPLEMENTED',
    'DESCRIPTOR_IDENTITY_FLOOR_SNAPSHOT_UNIMPLEMENTED',
    'CROSS_SERVICE_GLOBAL_SNAPSHOT_COMPOSITION_UNIMPLEMENTED',
    'INBOX_FRAME_BODY_AVAILABILITY_AND_HASH_VERIFICATION_UNIMPLEMENTED',
    'INBOX_WAL_STATE_MACHINE_AND_ENGINE_RESTORE_UNIMPLEMENTED',
    'SCALABLE_EXTERNAL_SORTED_CANDIDATE_STREAM_UNIMPLEMENTED',
    'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED'
  ])
})

export class BlindCellInboxControlSnapshotIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindCellInboxControlSnapshotIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function fail (message) {
  throw new BlindCellInboxControlSnapshotIntegrityError(message)
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
    fail('checkpointHeader is required for Cell+Inbox reconstruction')
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
    fail('Cell+Inbox semantic snapshot tuple does not match its checkpoint header')
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
  if (key[0] !== FAMILY.CELL && key[0] !== FAMILY.INBOX) {
    fail('Cell+Inbox composition rejects an uncovered control snapshot family')
  }
  return Object.freeze({ entryKind, key, value })
}

function compareEntries (left, right) {
  if (left.entryKind !== right.entryKind) return left.entryKind - right.entryKind
  return b4a.compare(left.key, right.key)
}

async function partitionEntries (input, maximumEntries, maximumBufferedBytes) {
  if (!input || (typeof input[Symbol.iterator] !== 'function' &&
      typeof input[Symbol.asyncIterator] !== 'function')) {
    fail('snapshot entries must be iterable')
  }
  const output = { cell: [], inbox: [], count: 0, bufferedBytes: 0 }
  let previous = null
  for await (const raw of input) {
    if (++output.count > maximumEntries) fail('Cell+Inbox snapshot exceeds its configured entry bound')
    const entry = copyEntry(raw)
    output.bufferedBytes += BUFFERED_ENTRY_OVERHEAD + entry.key.byteLength + entry.value.byteLength
    if (!Number.isSafeInteger(output.bufferedBytes) || output.bufferedBytes > maximumBufferedBytes) {
      fail('Cell+Inbox snapshot exceeds its configured buffered-byte bound')
    }
    if (previous && compareEntries(previous, entry) >= 0) {
      fail('Cell+Inbox snapshot entries are not strictly sorted and duplicate-free')
    }
    previous = entry
    if (entry.key[0] === FAMILY.CELL) output.cell.push(entry)
    else output.inbox.push(entry)
  }
  if (output.cell.length < 1 || output.inbox.length < 1) {
    fail('Cell+Inbox composition requires both complete family snapshots')
  }
  return output
}

function authorityState (authority) {
  const state = AUTHORITIES.get(authority)
  if (!state) throw new TypeError('a branded Cell+Inbox control snapshot semantic authority is required')
  return state
}

export function createBlindCellInboxControlSnapshotSemanticAuthority (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Cell+Inbox semantic authority options must be an object')
  }
  const cellVerifier = verifyBlindCellControlSnapshotSemanticVerifier(options.cellVerifier)
  const inboxVerifier = verifyBlindInboxControlSnapshotSemanticVerifier(options.inboxVerifier)
  const maximumEntries = options.maximumEntries == null
    ? 0x1000000
    : integer(options.maximumEntries, 2, 0x1000000, 'maximumEntries')
  const maximumBufferedBytes = options.maximumBufferedBytes == null
    ? DEFAULT_MAXIMUM_BUFFERED_BYTES
    : integer(options.maximumBufferedBytes, 256, MAXIMUM_BUFFERED_BYTES, 'maximumBufferedBytes')
  const authority = Object.freeze({
    kind: 'BLIND_CELL_INBOX_CONTROL_SNAPSHOT_RECOVERY_SEMANTIC_AUTHORITY_V1',
    allFamilyComposition: false,
    publicationAuthorized: false,
    productionComplete: false
  })
  AUTHORITIES.set(authority, Object.freeze({
    cellVerifier,
    inboxVerifier,
    maximumEntries,
    maximumBufferedBytes
  }))
  return authority
}

export async function reconstructBlindCellInboxControlSnapshot (authority, input = {}) {
  const state = authorityState(authority)
  const ownedTuple = tuple(input.header)
  // Snapshot the complete checkpoint header before awaiting an attacker-
  // controlled iterable. In particular, epochFloor must be identical for both
  // family reconstructions even when the supplied object has mutable getters.
  const ownedCheckpointTuple = checkpointTuple(input.checkpointHeader, ownedTuple)
  const declaredEntryCount = integer(input.declaredEntryCount, 2, state.maximumEntries, 'declaredEntryCount')
  const partitioned = await partitionEntries(
    input.entries,
    state.maximumEntries,
    state.maximumBufferedBytes
  )
  if (partitioned.count !== declaredEntryCount) {
    fail('Cell+Inbox semantic entry count does not match the declared snapshot count')
  }
  const childInput = entries => Object.freeze({
    header: ownedTuple,
    checkpointHeader: ownedCheckpointTuple,
    declaredEntryCount: entries.length,
    entries
  })
  // Avoid doubling the peak reconstruction workspace while the implementation
  // still buffers both family partitions in memory.
  const cellResult = await state.cellVerifier(childInput(partitioned.cell))
  const inboxResult = await state.inboxVerifier(childInput(partitioned.inbox))
  const expected = { ...ownedTuple }
  verifyBlindCellControlSnapshotSemanticResult(cellResult, {
    ...expected,
    entryCount: partitioned.cell.length
  })
  verifyBlindInboxControlSnapshotSemanticResult(inboxResult, {
    ...expected,
    entryCount: partitioned.inbox.length
  })
  if (cellResult.cellComplete !== true || inboxResult.inboxComplete !== true ||
      cellResult.recoveryVerified !== true || inboxResult.recoveryVerified !== true ||
      cellResult.publicationAuthorized !== false || inboxResult.publicationAuthorized !== false ||
      cellResult.productionComplete !== false || inboxResult.productionComplete !== false) {
    fail('family semantic results are not recovery-only complete results')
  }

  const verified = Object.freeze({
    ...ownedTuple,
    entryCount: partitioned.count,
    cellEntryCount: partitioned.cell.length,
    inboxEntryCount: partitioned.inbox.length,
    cellResult,
    inboxResult
  })
  const result = {}
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    Object.defineProperty(result, field, { enumerable: true, get: () => b4a.from(verified[field]) })
  }
  Object.defineProperty(result, 'cellState', { enumerable: true, get: () => verified.cellResult.cellState })
  Object.defineProperty(result, 'inboxState', { enumerable: true, get: () => verified.inboxResult.inboxState })
  for (const [field, value] of Object.entries({
    walSequence: verified.walSequence,
    entryCount: verified.entryCount,
    cellEntryCount: verified.cellEntryCount,
    inboxEntryCount: verified.inboxEntryCount,
    cellComplete: true,
    inboxComplete: true,
    cellInboxComplete: true,
    allFamilyComplete: false,
    recoveryVerified: true,
    publicationAuthorized: false,
    productionComplete: false,
    exclusions: BLIND_CELL_INBOX_CONTROL_SNAPSHOT_STATUS.exclusions
  })) Object.defineProperty(result, field, { enumerable: true, value })
  Object.freeze(result)
  VERIFIED_RESULTS.set(result, verified)
  return result
}

export function createBlindCellInboxControlSnapshotSemanticVerifier (authority) {
  const state = authorityState(authority)
  const verifier = input => reconstructBlindCellInboxControlSnapshot(authority, input)
  VERIFIERS.set(verifier, state)
  return verifier
}

export function verifyBlindCellInboxControlSnapshotSemanticVerifier (verifier) {
  if (!VERIFIERS.has(verifier)) throw new TypeError('a branded Cell+Inbox control snapshot semantic verifier is required')
  return verifier
}

export function verifyBlindCellInboxControlSnapshotSemanticResult (result, expected = {}) {
  const verified = VERIFIED_RESULTS.get(result)
  if (!verified) throw new TypeError('a branded Cell+Inbox control snapshot semantic result is required')
  for (const field of ['entryCount', 'cellEntryCount', 'inboxEntryCount']) {
    if (expected[field] != null && integer(expected[field], 1, 0x1000000, `expected ${field}`) !== verified[field]) {
      fail(`Cell+Inbox semantic result ${field} does not match`)
    }
  }
  if (expected.walSequence != null && u64(expected.walSequence, 'expected walSequence') !== verified.walSequence) {
    fail('Cell+Inbox semantic result walSequence does not match')
  }
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !b4a.equals(bytes(expected[field], 32, `expected ${field}`), verified[field])) {
      fail(`Cell+Inbox semantic result ${field} does not match`)
    }
  }
  verifyBlindCellControlSnapshotSemanticResult(verified.cellResult, {
    ...verified,
    entryCount: verified.cellEntryCount
  })
  verifyBlindInboxControlSnapshotSemanticResult(verified.inboxResult, {
    ...verified,
    entryCount: verified.inboxEntryCount
  })
  if (result.cellInboxComplete !== true || result.allFamilyComplete !== false ||
      result.recoveryVerified !== true || result.publicationAuthorized !== false ||
      result.productionComplete !== false) {
    fail('Cell+Inbox semantic result must remain partial and recovery-only')
  }
  return result
}
