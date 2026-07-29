import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY
} from '@hiverelay/blind-protocol'
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
  BLIND_CELL_INBOX_CONTROL_SNAPSHOT_STATUS,
  createBlindCellInboxControlSnapshotSemanticAuthority,
  createBlindCellInboxControlSnapshotSemanticVerifier,
  verifyBlindCellInboxControlSnapshotSemanticResult,
  verifyBlindCellInboxControlSnapshotSemanticVerifier
} from '../cell-inbox-control-snapshot.js'

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
  return left.entryKind === right.entryKind
    ? b4a.compare(left.key, right.key)
    : left.entryKind - right.entryKind
}

async function fixture () {
  const cellAuthority = createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
  const inboxAuthority = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
  const cellVerifier = createBlindCellControlSnapshotSemanticVerifier(cellAuthority)
  const inboxVerifier = createBlindInboxControlSnapshotSemanticVerifier(inboxAuthority)
  const authority = createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey: PARTITION_KEY,
    cellVerifier,
    inboxVerifier
  })
  const verifier = createBlindCellInboxControlSnapshotSemanticVerifier(authority)
  const entries = [
    ...await entriesFrom(streamBlindCellControlSnapshotEntries, cellAuthority, cellState()),
    ...await entriesFrom(streamBlindInboxControlSnapshotEntries, inboxAuthority, inboxState())
  ].sort(compareEntries)
  return { authority, verifier, entries }
}

test('Cell+Inbox composition verifies both complete families under one exact checkpoint tuple', async t => {
  const value = await fixture()
  t.is(verifyBlindCellInboxControlSnapshotSemanticVerifier(value.verifier), value.verifier)
  const result = await value.verifier({
    ...headers(),
    declaredEntryCount: value.entries.length,
    entries: value.entries
  })
  t.is(verifyBlindCellInboxControlSnapshotSemanticResult(result, {
    ...headers().header,
    entryCount: 2,
    cellEntryCount: 1,
    inboxEntryCount: 1
  }), result)
  t.is(result.cellComplete, true)
  t.is(result.inboxComplete, true)
  t.is(result.cellInboxComplete, true)
  t.is(result.allFamilyComplete, false)
  t.is(result.publicationAuthorized, false)
  t.is(result.productionComplete, false)
  t.is(result.cellState.cells.size, 0)
  t.is(result.inboxState.inboxes.size, 0)
  t.is(BLIND_CELL_INBOX_CONTROL_SNAPSHOT_STATUS.allFamilyCompositionImplemented, false)

  result.relayPublicKey.fill(0)
  result.cellState.accounting.stagingByProfile.set(7, 9)
  result.inboxState.inboxes.set('forged', {})
  verifyBlindCellInboxControlSnapshotSemanticResult(result, headers().header)
  t.alike(result.relayPublicKey, bytes(1))
  t.is(result.cellState.accounting.stagingByProfile.size, 0)
  t.is(result.inboxState.inboxes.size, 0)
})

test('Cell+Inbox composition rejects uncovered, incomplete, unsorted, duplicate, and misdeclared input', async t => {
  const value = await fixture()
  const input = entries => ({ ...headers(), declaredEntryCount: entries.length, entries })

  const uncovered = value.entries.map(entry => ({ ...entry, key: b4a.from(entry.key) }))
  uncovered[0].key[0] = FAMILY.CORE
  await t.exception(value.verifier(input(uncovered)), /rejects an uncovered control snapshot family/)

  await t.exception(value.verifier({
    ...input(value.entries.filter(entry => entry.key[0] === FAMILY.CELL)),
    declaredEntryCount: 2
  }), /requires both complete family snapshots/)
  await t.exception(value.verifier(input([...value.entries].reverse())), /not strictly sorted/)
  await t.exception(value.verifier(input([value.entries[0], value.entries[0], value.entries[1]])),
    /not strictly sorted/)
  await t.exception(value.verifier({ ...input(value.entries), declaredEntryCount: 3 }),
    /entry count does not match/)
})

test('Cell+Inbox composition snapshots one epoch floor and enforces a buffered-byte bound', async t => {
  const value = await fixture()
  const checkpointHeader = { ...headers().checkpointHeader }
  let epochReads = 0
  Object.defineProperty(checkpointHeader, 'epochFloor', {
    enumerable: true,
    get () { return 100 + epochReads++ }
  })
  const result = await value.verifier({
    header: headers().header,
    checkpointHeader,
    declaredEntryCount: value.entries.length,
    entries: value.entries
  })
  t.is(epochReads, 1)
  t.is(result.cellState.epochFloor, 100)
  t.is(result.inboxState.epochFloor, 100)

  const bounded = createBlindCellInboxControlSnapshotSemanticVerifier(
    createBlindCellInboxControlSnapshotSemanticAuthority({
      partitionKey: PARTITION_KEY,
      cellVerifier: createBlindCellControlSnapshotSemanticVerifier(
        createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })),
      inboxVerifier: createBlindInboxControlSnapshotSemanticVerifier(
        createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })),
      maximumBufferedBytes: 256
    })
  )
  const oversized = value.entries.map(entry => ({
    ...entry,
    key: b4a.from(entry.key),
    value: b4a.alloc(300)
  }))
  await t.exception(bounded({
    ...headers(),
    declaredEntryCount: oversized.length,
    entries: oversized
  }), /buffered-byte bound/)
})

test('Cell+Inbox authority and result brands cannot be forged or widened to all-family authority', async t => {
  const value = await fixture()
  await t.exception.all(() => createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey: PARTITION_KEY,
    cellVerifier: async () => {},
    inboxVerifier: async () => {}
  }), /branded Cell control snapshot semantic verifier/)
  await t.exception.all(() => verifyBlindCellInboxControlSnapshotSemanticVerifier(async () => {}),
    /branded Cell\+Inbox control snapshot semantic verifier/)
  const result = await value.verifier({ ...headers(), declaredEntryCount: 2, entries: value.entries })
  await t.exception.all(() => verifyBlindCellInboxControlSnapshotSemanticResult({ ...result }),
    /branded Cell\+Inbox control snapshot semantic result/)
  await t.exception.all(() => createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey: PARTITION_KEY,
    cellVerifier: createBlindCellControlSnapshotSemanticVerifier(
      createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })),
    inboxVerifier: createBlindInboxControlSnapshotSemanticVerifier(
      createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })),
    maximumEntries: 1
  }), /maximumEntries is outside/)
})

test('Cell+Inbox authority ignores removed legacy partition-secret input', t => {
  const cellVerifier = createBlindCellControlSnapshotSemanticVerifier(
    createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY }))
  const inboxVerifier = createBlindInboxControlSnapshotSemanticVerifier(
    createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY }))
  let reads = 0
  const options = { cellVerifier, inboxVerifier }
  Object.defineProperty(options, 'partitionKey', {
    enumerable: true,
    get () {
      reads++
      return reads === 1 ? PARTITION_KEY : b4a.alloc(32, 0x26)
    }
  })
  const verifier = createBlindCellInboxControlSnapshotSemanticVerifier(
    createBlindCellInboxControlSnapshotSemanticAuthority(options))
  t.is(reads, 0)
  t.is(verifyBlindCellInboxControlSnapshotSemanticVerifier(verifier), verifier)
})
