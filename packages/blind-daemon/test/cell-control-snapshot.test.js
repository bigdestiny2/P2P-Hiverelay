import b4a from 'b4a'
import test from 'brittle'
import { createHmac } from 'node:crypto'
import {
  CELL_SIZE_CLASS,
  allocationCommitment,
  blindCellAtomicCommittedPutSpendSnapshotV1,
  blindPreparedAdmissionStoreV1,
  blindCellControlGlobalSnapshotV1,
  blake2b256,
  cellStorageSlot,
  decodeCanonical,
  encodeCanonical,
  relayResultBindingV1
} from '@hiverelay/blind-protocol'
import {
  BLIND_CELL_CONTROL_SNAPSHOT_STATUS,
  createBlindCellControlSnapshotSemanticAuthority,
  createBlindCellControlSnapshotSemanticVerifier,
  reconstructBlindCellControlSnapshot,
  streamBlindCellControlSnapshotEntries,
  verifyBlindCellControlSnapshotSemanticResult,
  verifyBlindCellControlSnapshotSemanticVerifier
} from '../cell-control-snapshot.js'
import { verifyBlindLocalCheckpointSnapshotSemanticAuthority } from '../local-checkpoint-store.js'

const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.store-result-identity.v1', 'ascii')
const PARTITION_KEY = b4a.alloc(32, 0x05)

function bytes (fill) {
  return b4a.alloc(32, fill)
}

function u32bytes (value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64bytes (value) {
  value = BigInt(value)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
}

function resultIdentity (operation, slot, requestCommitment, blobHash, leaseClass, leaseEpoch, stateRevision) {
  return hashParts(
    RESULT_IDENTITY_DOMAIN,
    b4a.from(operation, 'ascii'),
    slot,
    requestCommitment,
    blobHash,
    b4a.from([leaseClass]),
    u32bytes(leaseEpoch),
    u64bytes(stateRevision)
  )
}

function virtualBucket (storageSlot) {
  const digest = createHmac('sha256', PARTITION_KEY)
    .update(b4a.from([2]))
    .update(storageSlot)
    .digest()
  return digest[0] * 0x100 + digest[1]
}

function profile1ResultBinding (relayPublicKey) {
  return encodeCanonical(relayResultBindingV1, {
    version: 1,
    relayPublicKey,
    storeId: bytes(0x02),
    descriptorSequence: 1n,
    descriptorHash: bytes(0x06),
    durabilityProfileId: 1,
    durabilityContinuityHash: bytes(0x03),
    durabilityProfileHash: bytes(0x07),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null
  })
}

function semanticAuthority () {
  return createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
}

function ingress (relayPublicKey, seed, overrides = {}) {
  const allocationEpoch = overrides.allocationEpoch == null ? 90 + seed : overrides.allocationEpoch
  const sizeClass = overrides.sizeClass == null ? 1 : overrides.sizeClass
  const leaseClass = overrides.leaseClass == null ? 1 : overrides.leaseClass
  const createPublicKey = bytes(0x20 + seed)
  const renewPublicKey = bytes(0x30 + seed)
  const dropPublicKey = bytes(0x40 + seed)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey })
  const declaredBlobHash = bytes(0x50 + seed)
  const allocation = allocationCommitment({
    relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey,
    renewPublicKey,
    dropPublicKey
  })
  const spendTag = bytes(0x60 + seed)
  const requestCommitment = bytes(0x70 + seed)
  const profileId = seed
  const declaredBytes = CELL_SIZE_CLASS[sizeClass]
  const preparedAdmissionBytes = encodeCanonical(blindPreparedAdmissionStoreV1, {
    version: 1,
    spendTag,
    requestCommitment,
    profileId,
    schemeId: 1,
    parameterHash: bytes(0x75 + seed),
    resourceClass: sizeClass,
    leaseClass,
    costUnits: 1n,
    walCommitRecord: bytes(0x76 + seed)
  })
  const requestFingerprint = hashParts(
    FINGERPRINT_DOMAIN,
    spendTag,
    requestCommitment,
    storageSlot,
    allocation,
    declaredBlobHash,
    u32bytes(declaredBytes),
    b4a.from([leaseClass]),
    u32bytes(profileId),
    blake2b256(preparedAdmissionBytes)
  )
  return {
    transactionId: bytes(0x10 + seed),
    spendTag,
    requestCommitment,
    requestFingerprint,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    declaredBlobHash,
    createPublicKey,
    renewPublicKey,
    dropPublicKey,
    allocationCommitment: allocation,
    profileId,
    preparedAdmissionBytes,
    resultBindingBytes: null,
    declaredBytes,
    deadlineUnixMillis: 100000n + BigInt(seed),
    remainingAttempts: 1,
    reservedEpoch: 100,
    terminalEpoch: null,
    resultIdentity: null,
    committedEpoch: null,
    inFlight: false
  }
}

function fixture (reverse = false) {
  const relayPublicKey = bytes(0x01)
  const committed = ingress(relayPublicKey, 1)
  committed.status = 'committed'
  committed.committedEpoch = 100
  committed.resultIdentity = resultIdentity(
    'stored',
    committed.storageSlot,
    committed.requestCommitment,
    committed.declaredBlobHash,
    committed.leaseClass,
    104,
    0n
  )
  const reserved = ingress(relayPublicKey, 2, { allocationEpoch: 98, leaseClass: 2 })
  reserved.status = 'reserved'
  reserved.remainingAttempts = 2
  const spendRows = [committed, reserved]
  if (reverse) spendRows.reverse()
  const spends = new Map(spendRows.map(value => [b4a.toString(value.spendTag, 'hex'), value]))
  const commitments = new Map(spendRows.map(value => [
    b4a.toString(value.requestCommitment, 'hex'),
    {
      spendKey: b4a.toString(value.spendTag, 'hex'),
      fingerprint: b4a.toString(value.requestFingerprint, 'hex')
    }
  ]))
  const cell = {
    storageSlot: committed.storageSlot,
    allocationEpoch: committed.allocationEpoch,
    sizeClass: committed.sizeClass,
    // A renewal mutates this field. The allocation commitment remains bound to
    // the original class 1, which the snapshot must recover separately.
    leaseClass: 4,
    leaseEpoch: 460,
    stateRevision: 1n,
    policyRevision: 0n,
    cellBlobHash: committed.declaredBlobHash,
    blobReference: { virtualBucket: virtualBucket(committed.storageSlot), objectId: bytes(0x81) },
    createPublicKey: committed.createPublicKey,
    renewPublicKey: committed.renewPublicKey,
    dropPublicKey: committed.dropPublicKey,
    allocationCommitment: committed.allocationCommitment,
    objectState: 1,
    policyState: 1,
    tombstoneReason: null,
    terminalEpoch: null,
    createSpendTag: committed.spendTag,
    resultIdentity: committed.resultIdentity,
    createdEpoch: 100
  }
  committed.resultCell = {
    storageSlot: committed.storageSlot,
    allocationEpoch: committed.allocationEpoch,
    sizeClass: committed.sizeClass,
    leaseClass: committed.leaseClass,
    leaseEpoch: 104,
    stateRevision: 0n,
    policyRevision: 0n,
    cellBlobHash: committed.declaredBlobHash,
    allocationCommitment: committed.allocationCommitment,
    objectState: 'PRESENT',
    policyState: 'VISIBLE'
  }
  return {
    relayPublicKey,
    storeId: bytes(0x02),
    durabilityContinuityHash: bytes(0x03),
    spends,
    commitments,
    requestResults: new Map(),
    cells: new Map([[b4a.toString(cell.storageSlot, 'hex'), cell]]),
    accounting: {
      storedBytes: CELL_SIZE_CLASS[1],
      stagingBytes: CELL_SIZE_CLASS[1],
      controlBytes: 2 * 512,
      tombstoneBytes: 2 * 512,
      reservedCells: 1,
      stagingByProfile: new Map([[reserved.profileId, reserved.declaredBytes]])
    },
    epochFloor: 100,
    clockUnsafe: true,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function fixtureWithAtomicCommittedPut () {
  const state = fixture()
  const atomic = ingress(state.relayPublicKey, 3, { allocationEpoch: 99 })
  atomic.status = 'committed'
  atomic.operation = null
  atomic.atomicCommitted = true
  atomic.resultBindingBytes = profile1ResultBinding(state.relayPublicKey)
  atomic.committedEpoch = 100
  atomic.resultIdentity = resultIdentity(
    'stored',
    atomic.storageSlot,
    atomic.requestCommitment,
    atomic.declaredBlobHash,
    atomic.leaseClass,
    104,
    0n
  )
  atomic.resultCell = {
    storageSlot: atomic.storageSlot,
    allocationEpoch: atomic.allocationEpoch,
    sizeClass: atomic.sizeClass,
    leaseClass: atomic.leaseClass,
    leaseEpoch: 104,
    stateRevision: 0n,
    policyRevision: 0n,
    cellBlobHash: atomic.declaredBlobHash,
    allocationCommitment: atomic.allocationCommitment,
    objectState: 'PRESENT',
    policyState: 'VISIBLE'
  }
  delete atomic.deadlineUnixMillis
  delete atomic.remainingAttempts
  delete atomic.reservedEpoch
  const spendKey = b4a.toString(atomic.spendTag, 'hex')
  const commitmentKey = b4a.toString(atomic.requestCommitment, 'hex')
  state.spends.set(spendKey, atomic)
  state.commitments.set(commitmentKey, {
    spendKey,
    fingerprint: b4a.toString(atomic.requestFingerprint, 'hex')
  })
  state.cells.set(b4a.toString(atomic.storageSlot, 'hex'), {
    storageSlot: atomic.storageSlot,
    allocationEpoch: atomic.allocationEpoch,
    sizeClass: atomic.sizeClass,
    leaseClass: atomic.leaseClass,
    leaseEpoch: 104,
    stateRevision: 0n,
    policyRevision: 0n,
    cellBlobHash: atomic.declaredBlobHash,
    blobReference: { virtualBucket: virtualBucket(atomic.storageSlot), objectId: bytes(0x82) },
    createPublicKey: atomic.createPublicKey,
    renewPublicKey: atomic.renewPublicKey,
    dropPublicKey: atomic.dropPublicKey,
    allocationCommitment: atomic.allocationCommitment,
    objectState: 1,
    policyState: 1,
    tombstoneReason: null,
    terminalEpoch: null,
    createSpendTag: atomic.spendTag,
    resultIdentity: atomic.resultIdentity,
    createdEpoch: atomic.committedEpoch
  })
  state.accounting.storedBytes += atomic.declaredBytes
  state.accounting.controlBytes += 512
  state.accounting.tombstoneBytes += 512
  return { state, atomic }
}

function headers (state) {
  const header = {
    relayPublicKey: state.relayPublicKey,
    storeId: bytes(0x02),
    durabilityContinuityHash: bytes(0x03),
    walSequence: 7n,
    walHash: bytes(0x04)
  }
  return {
    header,
    checkpointHeader: {
      relayPublicKey: header.relayPublicKey,
      storeId: header.storeId,
      durabilityContinuityHash: header.durabilityContinuityHash,
      coveredWalSequence: header.walSequence,
      coveredWalHash: header.walHash,
      epochFloor: state.epochFloor
    }
  }
}

async function entriesFor (authority, state) {
  const output = []
  for await (const entry of streamBlindCellControlSnapshotEntries(authority, state)) {
    output.push({ entryKind: entry.entryKind, key: b4a.from(entry.key), value: b4a.from(entry.value) })
  }
  return output
}

async function reconstruct (authority, state, entries) {
  const bound = headers(state)
  return reconstructBlindCellControlSnapshot(authority, {
    ...bound,
    declaredEntryCount: entries.length,
    entries
  })
}

test('Cell recovery snapshots are deterministic, exact, and preserve allocation history across renewals', async t => {
  const authority = semanticAuthority()
  const state = fixture()
  const entries = await entriesFor(authority, state)
  const reversedEntries = await entriesFor(authority, fixture(true))
  t.alike(reversedEntries, entries)

  const verifier = createBlindCellControlSnapshotSemanticVerifier(authority)
  t.is(verifyBlindCellControlSnapshotSemanticVerifier(verifier), verifier)
  const result = await verifier({
    ...headers(state),
    declaredEntryCount: entries.length,
    entries
  })
  t.is(verifyBlindCellControlSnapshotSemanticResult(result), result)
  t.is(result.cellComplete, true)
  t.is(result.recoveryVerified, true)
  t.is(result.publicationAuthorized, false)
  t.is(result.productionComplete, false)
  t.is(BLIND_CELL_CONTROL_SNAPSHOT_STATUS.scalableCandidateEntryStreamingImplemented, false)
  const recovered = result.cellState
  const cell = recovered.cells.values().next().value
  t.is(cell.allocationLeaseClass, 1)
  t.is(cell.leaseClass, 4)
  t.is(recovered.accounting.tombstoneBytes, 1024)
  t.is(recovered.accounting.stagingByProfile.get(2), CELL_SIZE_CLASS[1])
  t.is(recovered.epochFloor, 100)
  t.is(recovered.clockUnsafe, true)
})

test('atomic committed PUT checkpoints omit legacy reservation fields and reconstruct beside legacy state', async t => {
  const authority = semanticAuthority()
  const { state, atomic } = fixtureWithAtomicCommittedPut()
  const entries = await entriesFor(authority, state)
  const entry = entries.find(value => value.entryKind === 1 && value.key[1] === 5)
  t.ok(entry)
  const decoded = decodeCanonical(blindCellAtomicCommittedPutSpendSnapshotV1, entry.value, {
    copyBytes: true
  })
  t.absent(decoded.deadlineUnixMillis)
  t.absent(decoded.remainingAttempts)
  t.absent(decoded.reservedEpoch)
  t.alike(decoded.spendTag, atomic.spendTag)

  const recovered = (await reconstruct(authority, state, entries)).cellState
  const restored = recovered.spends.get(b4a.toString(atomic.spendTag, 'hex'))
  t.is(restored.atomicCommitted, true)
  t.absent(restored.deadlineUnixMillis)
  t.absent(restored.remainingAttempts)
  t.absent(restored.reservedEpoch)
  t.alike(restored.resultIdentity, atomic.resultIdentity)
  t.is(recovered.spends.size, 3)
  t.is(recovered.cells.size, 2)
  t.is(recovered.accounting.storedBytes, 2 * CELL_SIZE_CLASS[1])
})

test('Cell semantic result state and tuple copies cannot mutate the branded verification record', async t => {
  const authority = semanticAuthority()
  const state = fixture()
  const entries = await entriesFor(authority, state)
  const result = await reconstruct(authority, state, entries)
  const expected = headers(state).header

  const exposedRelay = result.relayPublicKey
  exposedRelay.fill(0)
  const exposedState = result.cellState
  exposedState.cells.clear()
  exposedState.spends.clear()
  exposedState.accounting.stagingByProfile.clear()
  verifyBlindCellControlSnapshotSemanticResult(result, {
    ...expected,
    entryCount: entries.length
  })
  t.alike(result.relayPublicKey, expected.relayPublicKey)
  t.is(result.cellState.cells.size, 1)
  t.is(result.cellState.spends.size, 2)

  const forged = { ...result, publicationAuthorized: true }
  await t.exception.all(() => verifyBlindCellControlSnapshotSemanticResult(forged), /branded Cell control snapshot semantic result/)
  await t.exception(verifyBlindLocalCheckpointSnapshotSemanticAuthority(
    result,
    {},
    '/private/tmp',
    {}
  ), /snapshot semantic authority is forged, expired, or unsupported/)
})

test('Cell reconstruction rejects unknown, duplicate, incomplete, substituted, and misaccounted state', async t => {
  const authority = semanticAuthority()
  const state = fixture()
  const entries = await entriesFor(authority, state)

  const unknown = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const cellIndex = unknown.findIndex(entry => entry.entryKind === 3)
  unknown[cellIndex].key[1] = 0xff
  await t.exception(reconstruct(authority, state, unknown), /unknown Cell control snapshot entry/)

  const duplicate = [...entries]
  duplicate.splice(1, 0, entries[0])
  await t.exception(reconstruct(authority, state, duplicate), /strictly sorted and duplicate-free/)

  const incomplete = entries.filter(entry => !(entry.entryKind === 6 && entry.key.byteLength === 2))
  await t.exception(reconstruct(authority, state, incomplete), /incomplete without its global record/)

  const substituted = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const reservationIndex = substituted.findIndex(entry => entry.entryKind === 2)
  substituted[reservationIndex].key[substituted[reservationIndex].key.byteLength - 1] ^= 1
  await t.exception(reconstruct(authority, state, substituted), /key does not match spendTag/)

  const misaccounted = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const globalIndex = misaccounted.findIndex(entry => entry.entryKind === 6 && entry.key.byteLength === 2)
  const global = decodeCanonical(blindCellControlGlobalSnapshotV1, misaccounted[globalIndex].value, { copyBytes: true })
  global.storedBytes++
  misaccounted[globalIndex].value = encodeCanonical(blindCellControlGlobalSnapshotV1, global)
  await t.exception(reconstruct(authority, state, misaccounted), /storedBytes accounting does not reconstruct exactly/)

  const nonCell = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  nonCell[0].key[0] = 3
  await t.exception(reconstruct(authority, state, nonCell), /rejects non-Cell snapshot entries/)

  const wrongBucketState = fixture()
  wrongBucketState.cells.values().next().value.blobReference.virtualBucket ^= 1
  await t.exception(entriesFor(authority, wrongBucketState), /blob virtual bucket does not match/)
})

test('candidate serialization rejects in-flight reservations and divergent derived indexes', async t => {
  await t.exception.all(() => createBlindCellControlSnapshotSemanticAuthority(), /partitionKey must be bytes/)
  const authority = semanticAuthority()
  const inFlight = fixture()
  for (const value of inFlight.spends.values()) {
    if (value.status === 'reserved') value.inFlight = true
  }
  await t.exception(entriesFor(authority, inFlight), /in-flight Cell reservations cannot enter a checkpoint/)

  const divergent = fixture()
  divergent.commitments.values().next().value.fingerprint = '00'.repeat(32)
  await t.exception(entriesFor(authority, divergent), /commitment index does not match reconstructed spends/)

  const shortLease = fixture()
  shortLease.cells.values().next().value.leaseEpoch = 103
  await t.exception(entriesFor(authority, shortLease), /leaseEpoch is below its initial allocation lease/)

  const zeroRevisionTombstone = fixture()
  const tombstone = zeroRevisionTombstone.cells.values().next().value
  tombstone.objectState = 2
  tombstone.tombstoneReason = 1
  tombstone.terminalEpoch = 100
  tombstone.stateRevision = 0n
  zeroRevisionTombstone.accounting.storedBytes = 0
  await t.exception(entriesFor(authority, zeroRevisionTombstone), /tombstone must have a nonzero state revision/)

  const exhausted = fixture()
  const terminal = [...exhausted.spends.values()].find(value => value.status === 'reserved')
  terminal.status = 'terminal'
  terminal.terminalReason = 2
  terminal.terminalEpoch = 100
  terminal.remainingAttempts = 1
  exhausted.accounting.stagingBytes = 0
  exhausted.accounting.reservedCells = 0
  exhausted.accounting.tombstoneBytes = 512
  exhausted.accounting.stagingByProfile.clear()
  await t.exception(entriesFor(authority, exhausted), /attempts-exhausted Cell terminal spend must have zero/)
})
