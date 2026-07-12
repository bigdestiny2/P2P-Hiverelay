import b4a from 'b4a'
import test from 'brittle'
import { FAMILY } from '@hiverelay/blind-protocol'
import {
  createBlindCellControlSnapshotSemanticAuthority,
  createBlindCellControlSnapshotSemanticVerifier,
  streamBlindCellControlSnapshotEntries
} from '../cell-control-snapshot.js'
import {
  createBlindInboxControlSnapshotSemanticAuthority,
  createBlindInboxControlSnapshotSemanticVerifier,
  streamBlindInboxControlSnapshotEntries
} from '../inbox-control-snapshot.js'
import {
  createBlindCellInboxControlSnapshotSemanticAuthority,
  createBlindCellInboxControlSnapshotSemanticVerifier
} from '../cell-inbox-control-snapshot.js'
import {
  createBlindCoreControlSnapshotSemanticAuthority,
  createBlindCoreControlSnapshotSemanticVerifier,
  streamBlindCoreControlSnapshotEntries
} from '../core-control-snapshot.js'
import {
  BLIND_CELL_INBOX_CORE_CONTROL_SNAPSHOT_STATUS,
  createBlindCellInboxCoreControlSnapshotSemanticAuthority,
  createBlindCellInboxCoreControlSnapshotSemanticVerifier,
  verifyBlindCellInboxCoreControlSnapshotSemanticResult,
  verifyBlindCellInboxCoreControlSnapshotSemanticVerifier
} from '../cell-inbox-core-control-snapshot.js'

const PARTITION_KEY = b4a.alloc(32, 0x25)

function bytes (fill) {
  return b4a.alloc(32, fill)
}

function cellState () {
  return {
    relayPublicKey: bytes(1),
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    cells: new Map(),
    accounting: {
      storedBytes: 0,
      stagingBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      reservedCells: 0,
      stagingByProfile: new Map()
    },
    epochFloor: 100,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function inboxState () {
  return {
    relayPublicKey: bytes(1),
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    inboxes: new Map(),
    frames: new Map(),
    retryPins: new Map(),
    accounting: {
      storedFrameBytes: 0,
      stagingFrameBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      frameIndexBytes: 0,
      reservedFrames: 0,
      stagingByProfile: new Map()
    },
    epochFloor: 100,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function coreState () {
  return {
    relayPublicKey: bytes(1),
    storeId: bytes(2),
    durabilityContinuityHash: bytes(3),
    recordsByLogical: new Map(),
    recordsBySpend: new Map(),
    controlChannels: new Map(),
    epochFloor: 100,
    clockUnsafe: false,
    readOnlyReason: null
  }
}

function headers () {
  const header = {
    relayPublicKey: bytes(1),
    storeId: bytes(2),
    durabilityContinuityHash: bytes(3),
    walSequence: 7n,
    walHash: bytes(4)
  }
  return {
    header,
    checkpointHeader: {
      relayPublicKey: header.relayPublicKey,
      storeId: header.storeId,
      durabilityContinuityHash: header.durabilityContinuityHash,
      coveredWalSequence: header.walSequence,
      coveredWalHash: header.walHash,
      epochFloor: 100
    }
  }
}

async function entriesFrom (stream, authority, state) {
  const entries = []
  for await (const entry of stream(authority, state)) {
    entries.push({ entryKind: entry.entryKind, key: b4a.from(entry.key), value: b4a.from(entry.value) })
  }
  return entries
}

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

async function fixture (overrides = {}) {
  const partitionKey = overrides.partitionKey || PARTITION_KEY
  const cellAuthority = createBlindCellControlSnapshotSemanticAuthority({ partitionKey })
  const inboxAuthority = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey })
  const coreAuthority = createBlindCoreControlSnapshotSemanticAuthority({
    partitionKey: overrides.corePartitionKey || partitionKey
  })
  const cellInboxAuthority = createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey,
    cellVerifier: createBlindCellControlSnapshotSemanticVerifier(cellAuthority),
    inboxVerifier: createBlindInboxControlSnapshotSemanticVerifier(inboxAuthority)
  })
  const authority = createBlindCellInboxCoreControlSnapshotSemanticAuthority({
    partitionKey,
    cellInboxVerifier: createBlindCellInboxControlSnapshotSemanticVerifier(cellInboxAuthority),
    coreVerifier: createBlindCoreControlSnapshotSemanticVerifier(coreAuthority)
  })
  const verifier = createBlindCellInboxCoreControlSnapshotSemanticVerifier(authority)
  const entries = [
    ...await entriesFrom(streamBlindCellControlSnapshotEntries, cellAuthority, cellState()),
    ...await entriesFrom(streamBlindInboxControlSnapshotEntries, inboxAuthority, inboxState()),
    ...await entriesFrom(streamBlindCoreControlSnapshotEntries, coreAuthority, coreState())
  ].sort(compareEntries)
  return { authority, verifier, entries }
}

test('Cell+Inbox+Core composition verifies the three recovery fragments under one tuple', async t => {
  const value = await fixture()
  t.is(verifyBlindCellInboxCoreControlSnapshotSemanticVerifier(value.verifier), value.verifier)
  const result = await value.verifier({
    ...headers(),
    declaredEntryCount: value.entries.length,
    entries: value.entries
  })
  t.is(verifyBlindCellInboxCoreControlSnapshotSemanticResult(result, {
    ...headers().header,
    entryCount: 3,
    cellInboxEntryCount: 2,
    coreEntryCount: 1
  }), result)
  t.is(result.cellInboxCoreRetryComplete, true)
  t.is(result.coreOpenReplicationRetryComplete, true)
  t.is(result.coreComplete, false)
  t.is(result.allFamilyComplete, false)
  t.is(result.publicationAuthorized, false)
  t.is(result.productionComplete, false)
  t.is(result.cellState.cells.size, 0)
  t.is(result.inboxState.inboxes.size, 0)
  t.is(result.coreState.recordsByLogical.size, 0)
  t.is(BLIND_CELL_INBOX_CORE_CONTROL_SNAPSHOT_STATUS.allFamilyCompositionImplemented, false)
})

test('Cell+Inbox+Core composition rejects uncovered, missing, unsorted, duplicate, and forged inputs', async t => {
  const value = await fixture()
  const input = entries => ({ ...headers(), declaredEntryCount: entries.length, entries })
  const uncovered = value.entries.map(entry => ({ ...entry, key: b4a.from(entry.key) }))
  uncovered[0].key[0] = FAMILY.FORWARD
  await t.exception(value.verifier(input(uncovered)), /rejects an uncovered/)
  await t.exception(value.verifier(input(value.entries.filter(entry => entry.key[0] !== FAMILY.CORE))),
    /declaredEntryCount|requires all three/)
  await t.exception(value.verifier(input([...value.entries].reverse())), /not strictly sorted/)
  await t.exception(value.verifier(input([value.entries[0], value.entries[0], ...value.entries.slice(1)])),
    /not strictly sorted/)
  await t.exception.all(() => verifyBlindCellInboxCoreControlSnapshotSemanticVerifier(async () => {}),
    /branded Cell\+Inbox\+Core/)
  const result = await value.verifier(input(value.entries))
  await t.exception.all(() => verifyBlindCellInboxCoreControlSnapshotSemanticResult({ ...result }),
    /branded Cell\+Inbox\+Core/)
})

test('Cell+Inbox+Core composition rejects a Core verifier with a different private partition key', async t => {
  await t.exception(fixture({ corePartitionKey: b4a.alloc(32, 0x26) }), /partition key does not match/)
})
