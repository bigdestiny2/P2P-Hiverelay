// Derived from the frozen cell-control-snapshot.test.js fixture helpers. Synthetic state, no live store.
import b4a from 'b4a'
import { CELL_SIZE_CLASS, allocationCommitment, blindPreparedAdmissionStoreV1, blake2b256, cellStorageSlot, encodeCanonical, relayResultBindingV1 } from '../index.js'
import { deriveBlindVirtualBucket } from '../../blind-daemon/virtual-bucket.js'
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.store-result-identity.v1', 'ascii')

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
  return deriveBlindVirtualBucket(2, storageSlot)
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

export function populatedCellState () {
  const { state } = fixtureWithAtomicCommittedPut()
  // Drain the fixture's one reservation into retained terminal evidence; remove no spend.
  const pending = [...state.spends.values()].find(s => s.status === 'reserved')
  Object.assign(pending, { status: 'terminal', remainingAttempts: 0, terminalReason: 2, terminalEpoch: 100 })
  state.accounting.stagingBytes = 0
  state.accounting.reservedCells = 0
  state.accounting.tombstoneBytes -= 512
  state.accounting.stagingByProfile.clear()
  return state
}
