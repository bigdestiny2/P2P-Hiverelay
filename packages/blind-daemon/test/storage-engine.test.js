import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createHmac,
  generateKeyPairSync,
  sign
} from 'node:crypto'
import b4a from 'b4a'
import {
  allocationCommitment,
  blake2b256,
  blindPreparedAdmissionStoreV1,
  blindPutAtomicCommittedStoreV1,
  blindWalHeaderV2,
  cellManageRequestCommitment,
  cellPutRequestCommitment,
  cellStorageSlot,
  decodeCanonical,
  decodeStoreFormatAuthorityV1,
  encodeCanonical,
  relayResultBindingV1
} from '@hiverelay/blind-protocol'
import { PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY } from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  BLIND_CELL_STORAGE_LIMITS,
  BLIND_CELL_WAL_TYPE,
  BlindCellStorageEngine,
  BlindCellStorageError,
  verifyBlindCellStorageControlSnapshotState
} from '../storage-engine.js'
import {
  BLIND_STORE_SERVICE_TAG,
  BlindTransactionStore,
  BlindWalIntegrityError
} from '../transaction-store.js'

const EPOCH_MILLIS = 21600000n
const DURABILITY_CONTINUITY_HASH = b4a.alloc(32, 0x94)
const RELAY_PUBLIC_KEY = b4a.alloc(32, 0x71)
const PARTITION_KEY = b4a.alloc(32, 0x81)
const FENCE_HASH = b4a.alloc(32, 0x91)
const STORE_ID = b4a.alloc(32, 0x95)
const DURABILITY_PROFILE_HASH = b4a.alloc(32, 0x96)
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.store-result-identity.v1', 'ascii')
const ATOMIC_RECOVERY_SCRATCH = fileURLToPath(new URL('../../../.t/blind-cell-atomic-recovery/', import.meta.url))
const STORE_FORMAT_AUTHORITY_URL = new URL(
  '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
  import.meta.url
)
const BLIND_PROTOCOL_PACKAGE_URL = new URL('../../blind-protocol/package.json', import.meta.url)

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

function storedResultIdentity (slot, requestCommitment, blobHash, leaseClass, leaseEpoch) {
  return hashParts(
    RESULT_IDENTITY_DOMAIN,
    b4a.from('stored', 'ascii'),
    slot,
    requestCommitment,
    blobHash,
    b4a.from([leaseClass]),
    u32bytes(leaseEpoch),
    u64bytes(0n)
  )
}

function profile1ResultBindingBytes (overrides = {}) {
  return encodeCanonical(relayResultBindingV1, {
    version: 1,
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x97),
    durabilityProfileId: 1,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH,
    durabilityProfileHash: DURABILITY_PROFILE_HASH,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null,
    ...overrides
  })
}

function rawEd25519KeyPair () {
  const pair = generateKeyPairSync('ed25519')
  const der = pair.publicKey.export({ format: 'der', type: 'spki' })
  return { privateKey: pair.privateKey, publicKey: b4a.from(der.subarray(der.byteLength - 32)) }
}

function managementKeys () {
  return {
    create: rawEd25519KeyPair(),
    renew: rawEd25519KeyPair(),
    drop: rawEd25519KeyPair()
  }
}

function clock (epoch = 1000) {
  return {
    epoch,
    offsetMillis: 0n,
    now () { return BigInt(this.epoch) * EPOCH_MILLIS + this.offsetMillis }
  }
}

function options (root, time, overrides = {}) {
  return {
    root,
    relayPublicKey: RELAY_PUBLIC_KEY,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH,
    durabilityProfileId: 1,
    initialEpochFloor: time.epoch,
    nowUnixMillis: () => time.now(),
    autoClock: false,
    ...overrides
  }
}

function putFixture (fixture = {}) {
  const keys = fixture.keys || managementKeys()
  const allocationEpoch = fixture.allocationEpoch == null ? 1000 : fixture.allocationEpoch
  const sizeClass = fixture.sizeClass == null ? 1 : fixture.sizeClass
  const leaseClass = fixture.leaseClass == null ? 1 : fixture.leaseClass
  const cellBlob = fixture.cellBlob || b4a.alloc(4096, fixture.blobByte == null ? 0xa1 : fixture.blobByte)
  const declaredBlobHash = fixture.declaredBlobHash || blake2b256(cellBlob)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: keys.create.publicKey })
  const allocation = allocationCommitment({
    relayPublicKey: RELAY_PUBLIC_KEY,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: keys.create.publicKey,
    renewPublicKey: keys.renew.publicKey,
    dropPublicKey: keys.drop.publicKey
  })
  const clientNonce = fixture.clientNonce || b4a.alloc(32, fixture.nonceByte == null ? 0xb1 : fixture.nonceByte)
  const requestCommitment = cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce })
  const request = {
    version: 1,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    clientNonce,
    createPublicKey: keys.create.publicKey,
    renewPublicKey: keys.renew.publicKey,
    dropPublicKey: keys.drop.publicKey,
    declaredBlobHash,
    createSignature: sign(null, allocation, keys.create.privateKey)
  }
  return {
    keys,
    cellBlob,
    request,
    preparedAdmission: {
      spendTag: fixture.spendTag || b4a.alloc(32, fixture.spendByte == null ? 0xc1 : fixture.spendByte),
      requestCommitment,
      profileId: fixture.profileId == null ? 1 : fixture.profileId,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0xc7),
      costClass: { resourceClass: sizeClass, leaseClass, costUnits: 1n },
      walCommitRecord: b4a.alloc(32, 0xc8)
    },
    source: fixture.source == null ? cellBlob : fixture.source
  }
}

function preparedAdmissionBytesFor (fixture, overrides = {}) {
  return encodeCanonical(blindPreparedAdmissionStoreV1, {
    version: 1,
    spendTag: fixture.preparedAdmission.spendTag,
    requestCommitment: fixture.preparedAdmission.requestCommitment,
    profileId: fixture.preparedAdmission.profileId,
    schemeId: fixture.preparedAdmission.schemeId,
    parameterHash: fixture.preparedAdmission.parameterHash,
    resourceClass: fixture.preparedAdmission.costClass.resourceClass,
    leaseClass: fixture.preparedAdmission.costClass.leaseClass,
    costUnits: fixture.preparedAdmission.costClass.costUnits,
    walCommitRecord: fixture.preparedAdmission.walCommitRecord,
    ...overrides
  })
}

async function atomicCommitCandidate (engine, time, fixture) {
  const preparedAdmissionBytes = preparedAdmissionBytesFor(fixture)
  const allocation = allocationCommitment({
    relayPublicKey: RELAY_PUBLIC_KEY,
    storageSlot: fixture.request.storageSlot,
    allocationEpoch: fixture.request.allocationEpoch,
    sizeClass: fixture.request.sizeClass,
    leaseClass: fixture.request.leaseClass,
    declaredCellBlobHash: fixture.request.declaredBlobHash,
    createPublicKey: fixture.request.createPublicKey,
    renewPublicKey: fixture.request.renewPublicKey,
    dropPublicKey: fixture.request.dropPublicKey
  })
  const requestFingerprint = hashParts(
    FINGERPRINT_DOMAIN,
    fixture.preparedAdmission.spendTag,
    fixture.preparedAdmission.requestCommitment,
    fixture.request.storageSlot,
    allocation,
    fixture.request.declaredBlobHash,
    u32bytes(fixture.cellBlob.byteLength),
    b4a.from([fixture.request.leaseClass]),
    u32bytes(fixture.preparedAdmission.profileId),
    blake2b256(preparedAdmissionBytes)
  )
  const resultBindingBytes = profile1ResultBindingBytes()
  const virtualBucket = engine.transactionStore.virtualBucket(
    BLIND_STORE_SERVICE_TAG.CELL,
    fixture.request.storageSlot
  )
  const staged = await engine.transactionStore.stageOpaque({
    source: fixture.cellBlob,
    expectedLength: fixture.cellBlob.byteLength,
    expectedHash: fixture.request.declaredBlobHash,
    deadlineUnixMillis: time.now() + 10000n,
    nowUnixMillis: () => time.now()
  })
  const reference = await engine.transactionStore.publishOpaque(staged, virtualBucket)
  const leaseEpoch = time.epoch + BLIND_CELL_STORAGE_LIMITS.leaseEpochs[fixture.request.leaseClass]
  const resultIdentity = storedResultIdentity(
    fixture.request.storageSlot,
    fixture.preparedAdmission.requestCommitment,
    fixture.request.declaredBlobHash,
    fixture.request.leaseClass,
    leaseEpoch
  )
  return {
    transactionId: engine.transactionStore.newTransactionId(),
    virtualBucket,
    reference,
    payload: {
      version: 1,
      spendTag: fixture.preparedAdmission.spendTag,
      requestCommitment: fixture.preparedAdmission.requestCommitment,
      requestFingerprint,
      storageSlot: fixture.request.storageSlot,
      allocationEpoch: fixture.request.allocationEpoch,
      sizeClass: fixture.request.sizeClass,
      leaseClass: fixture.request.leaseClass,
      declaredBlobHash: fixture.request.declaredBlobHash,
      createPublicKey: fixture.request.createPublicKey,
      renewPublicKey: fixture.request.renewPublicKey,
      dropPublicKey: fixture.request.dropPublicKey,
      allocationCommitment: allocation,
      profileId: fixture.preparedAdmission.profileId,
      preparedAdmissionBytes,
      resultBindingBytes,
      declaredBytes: fixture.cellBlob.byteLength,
      blobObjectId: reference.objectId,
      leaseEpoch,
      stateRevision: 0n,
      policyRevision: 0n,
      resultIdentity,
      committedEpoch: time.epoch
    }
  }
}

function recoveryState (engine) {
  return {
    spends: [...engine.spends.keys()].sort(),
    commitments: [...engine.commitments.keys()].sort(),
    requestResults: [...engine.requestResults.keys()].sort(),
    cells: [...engine.cells.entries()].map(([key, value]) => ({
      key,
      virtualBucket: value.blobReference.virtualBucket,
      objectId: b4a.toString(value.blobReference.objectId, 'hex')
    })).sort((left, right) => left.key.localeCompare(right.key)),
    accounting: {
      storedBytes: engine.accounting.storedBytes,
      stagingBytes: engine.accounting.stagingBytes,
      controlBytes: engine.accounting.controlBytes,
      tombstoneBytes: engine.accounting.tombstoneBytes,
      reservedCells: engine.accounting.reservedCells,
      stagingByProfile: [...engine.accounting.stagingByProfile.entries()]
        .sort(([left], [right]) => left - right)
    },
    epochFloor: engine.epochFloor,
    clockUnsafe: engine.clockUnsafe,
    readOnlyReason: engine.readOnlyReason,
    integrityEvidence: engine.integrityEvidence.length
  }
}

function opaqueBlobPath (root, reference) {
  return path.join(
    root,
    'blobs',
    reference.virtualBucket.toString(16).padStart(4, '0'),
    `${b4a.toString(reference.objectId, 'hex')}.blob`
  )
}

function renewRequest (fixture, record, time, overrides = {}) {
  const request = {
    storageSlot: fixture.request.storageSlot,
    expectedRevision: record.stateRevision,
    expectedLeaseEpoch: record.leaseEpoch,
    leaseClass: overrides.leaseClass == null ? 1 : overrides.leaseClass,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0xd1)
  }
  const commitment = cellManageRequestCommitment({
    operation: 'cell-renew',
    relayPublicKey: RELAY_PUBLIC_KEY,
    storageSlot: request.storageSlot,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: request.leaseClass,
    clientNonce: request.clientNonce
  })
  request.signature = sign(null, commitment, fixture.keys.renew.privateKey)
  return {
    request,
    preparedAdmission: {
      spendTag: overrides.spendTag || b4a.alloc(32, 0xd2),
      requestCommitment: commitment,
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0xd7),
      costClass: { resourceClass: record.sizeClass, leaseClass: request.leaseClass, costUnits: 1n },
      walCommitRecord: b4a.alloc(32, 0xd8)
    },
    observedEpoch: time.epoch
  }
}

function dropRequest (fixture, record, overrides = {}) {
  const request = {
    storageSlot: fixture.request.storageSlot,
    expectedRevision: record.stateRevision,
    expectedLeaseEpoch: record.leaseEpoch,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0xe1)
  }
  const commitment = cellManageRequestCommitment({
    operation: 'cell-drop',
    relayPublicKey: RELAY_PUBLIC_KEY,
    storageSlot: request.storageSlot,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce: request.clientNonce
  })
  request.signature = sign(null, commitment, fixture.keys.drop.privateKey)
  return request
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

async function temporaryRoot (t, name) {
  const root = await fs.mkdtemp(`/private/tmp/${name}-`)
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function containedAtomicRecoveryRoot (t, name) {
  await fs.mkdir(ATOMIC_RECOVERY_SCRATCH, { recursive: true, mode: 0o700 })
  const root = await fs.mkdtemp(path.join(ATOMIC_RECOVERY_SCRATCH, `${name}-`))
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function zeroLastWalTransactionId (root) {
  const walPath = path.join(root, 'control', 'wal.v2')
  const bytes = await fs.readFile(walPath)
  let offset = 0
  let lastOffset = null
  while (offset < bytes.byteLength) {
    if (offset + 10 > bytes.byteLength) throw new Error('test WAL is truncated before its last frame')
    lastOffset = offset
    const totalLength = b4a.readUInt32BE(bytes, offset + 6)
    if (totalLength < 224 || offset + totalLength > bytes.byteLength) {
      throw new Error('test WAL has an invalid frame length')
    }
    offset += totalLength
  }
  if (offset !== bytes.byteLength || lastOffset == null) throw new Error('test WAL has no complete frame')
  const handle = await fs.open(walPath, 'r+')
  try {
    await handle.write(b4a.alloc(32), 0, 32, lastOffset + 18)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

const MALFORMED_ATOMIC_RECOVERY_CASES = Object.freeze([
  {
    name: 'duplicate spend',
    baseline: true,
    mutate (candidate, { baseline }) {
      candidate.payload.spendTag = baseline.preparedAdmission.spendTag
    },
    error: /redefines an existing spend, commitment, or cell/
  },
  {
    name: 'duplicate request commitment',
    baseline: true,
    mutate (candidate, { baseline }) {
      candidate.payload.requestCommitment = baseline.preparedAdmission.requestCommitment
    },
    error: /redefines an existing spend, commitment, or cell/
  },
  {
    name: 'duplicate storage slot',
    baseline: true,
    mutate (candidate, { baseline, engine }) {
      candidate.payload.storageSlot = baseline.request.storageSlot
      candidate.virtualBucket = engine.transactionStore.virtualBucket(
        BLIND_STORE_SERVICE_TAG.CELL,
        candidate.payload.storageSlot
      )
    },
    error: /redefines an existing spend, commitment, or cell/
  },
  {
    name: 'wrong virtual bucket',
    mutate (candidate) {
      candidate.virtualBucket = (candidate.virtualBucket + 1) & 0xffff
    },
    error: /virtual bucket/
  },
  {
    name: 'zero WAL transaction ID',
    zeroTransactionId: true,
    error: /transaction ID must be nonzero/
  },
  {
    name: 'size-class byte mismatch',
    mutate (candidate) {
      candidate.payload.declaredBytes += 4096
    },
    error: /size class and declared bytes disagree/
  },
  {
    name: 'non-self-certifying storage slot',
    mutate (candidate, { engine }) {
      candidate.payload.storageSlot = b4a.alloc(32, 0x55)
      candidate.virtualBucket = engine.transactionStore.virtualBucket(
        BLIND_STORE_SERVICE_TAG.CELL,
        candidate.payload.storageSlot
      )
    },
    error: /storage slot is not self-certifying/
  },
  {
    name: 'duplicate management keys',
    mutate (candidate) {
      candidate.payload.dropPublicKey = candidate.payload.renewPublicKey
    },
    error: /management keys must be distinct/
  },
  {
    name: 'allocation commitment mismatch',
    mutate (candidate) {
      candidate.payload.allocationCommitment = b4a.from(candidate.payload.allocationCommitment)
      candidate.payload.allocationCommitment[0] ^= 1
    },
    error: /allocation commitment mismatch/
  },
  {
    name: 'result binding names another store',
    mutate (candidate) {
      candidate.payload.resultBindingBytes = profile1ResultBindingBytes({
        storeId: b4a.alloc(32, 0xee)
      })
    },
    error: /does not bind this profile-1 relay\/store authority/
  },
  {
    name: 'noncanonical result binding',
    mutate (candidate) {
      candidate.payload.resultBindingBytes = b4a.concat([
        candidate.payload.resultBindingBytes,
        b4a.from([0])
      ])
    },
    error: /not a canonical relay result binding/
  },
  {
    name: 'prepared admission binding mismatch',
    mutate (candidate, { atomic }) {
      candidate.payload.preparedAdmissionBytes = preparedAdmissionBytesFor(atomic, {
        spendTag: b4a.alloc(32, 0xed)
      })
    },
    error: /binding mismatch/
  },
  {
    name: 'noncanonical prepared admission',
    mutate (candidate) {
      candidate.payload.preparedAdmissionBytes = b4a.concat([
        candidate.payload.preparedAdmissionBytes,
        b4a.from([0])
      ])
    },
    error: /trailing bytes/
  },
  {
    name: 'request fingerprint mismatch',
    mutate (candidate) {
      candidate.payload.requestFingerprint = b4a.from(candidate.payload.requestFingerprint)
      candidate.payload.requestFingerprint[0] ^= 1
    },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  },
  {
    name: 'lease epoch mismatch',
    mutate (candidate) {
      candidate.payload.leaseEpoch++
      candidate.payload.resultIdentity = storedResultIdentity(
        candidate.payload.storageSlot,
        candidate.payload.requestCommitment,
        candidate.payload.declaredBlobHash,
        candidate.payload.leaseClass,
        candidate.payload.leaseEpoch
      )
    },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  },
  {
    name: 'result identity mismatch',
    mutate (candidate) {
      candidate.payload.resultIdentity = b4a.from(candidate.payload.resultIdentity)
      candidate.payload.resultIdentity[0] ^= 1
    },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  },
  {
    name: 'committed epoch mismatch',
    mutate (candidate) {
      candidate.payload.committedEpoch++
      candidate.payload.leaseEpoch = candidate.payload.committedEpoch +
        BLIND_CELL_STORAGE_LIMITS.leaseEpochs[candidate.payload.leaseClass]
      candidate.payload.resultIdentity = storedResultIdentity(
        candidate.payload.storageSlot,
        candidate.payload.requestCommitment,
        candidate.payload.declaredBlobHash,
        candidate.payload.leaseClass,
        candidate.payload.leaseEpoch
      )
    },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  },
  {
    name: 'allocation epoch is too far in the future',
    allocationEpoch (time) { return time.epoch + 2 },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  },
  {
    name: 'allocation epoch exceeds the retention window',
    allocationEpoch (time) {
      return time.epoch - BLIND_CELL_STORAGE_LIMITS.retentionHorizonEpochs
    },
    error: /fingerprint, lease, allocation epoch, or result binding is invalid/
  }
])

async function findOnlyBlob (root) {
  const bucketNames = await fs.readdir(path.join(root, 'blobs'))
  const files = []
  for (const bucketName of bucketNames) {
    const names = await fs.readdir(path.join(root, 'blobs', bucketName))
    for (const name of names) files.push(path.join(root, 'blobs', bucketName, name))
  }
  if (files.length !== 1) throw new Error(`expected one blob, found ${files.length}`)
  return files[0]
}

test('transaction store uses keyed app-agnostic buckets and truncates only an incomplete WAL tail', async t => {
  const root = await temporaryRoot(t, 'blind-transaction-store')
  const frames = []
  const store = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  await store.open(frame => frames.push(frame))
  const locator = b4a.alloc(32, 0x31)
  const digest = createHmac('sha256', PARTITION_KEY)
    .update(b4a.from([BLIND_STORE_SERVICE_TAG.CELL]))
    .update(locator)
    .digest()
  const expectedBucket = digest[0] * 256 + digest[1]
  t.is(store.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, locator), expectedBucket)
  const appended = await store.append({
    type: 201,
    transactionId: b4a.alloc(32, 0x41),
    virtualBucket: expectedBucket,
    payload: b4a.from('opaque-control', 'ascii')
  })
  t.is(appended.sequence, 1n)
  await store.close()

  const walPath = path.join(root, 'control', 'wal.v2')
  const exactFrame = await fs.readFile(walPath)
  const header = decodeCanonical(blindWalHeaderV2, exactFrame.subarray(0, 192), { copyBytes: true })
  t.is(header.walVersion, 2)
  t.is(header.totalLength, exactFrame.byteLength)
  t.alike(header.durabilityContinuityHash, DURABILITY_CONTINUITY_HASH)
  const completeSize = (await fs.stat(walPath)).size
  await fs.appendFile(walPath, b4a.alloc(17, 0xff))
  const recovered = []
  const reopened = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  await reopened.open(frame => recovered.push(frame))
  t.is(recovered.length, 1)
  t.is(recovered[0].sequence, 1n)
  t.is((await fs.stat(walPath)).size, completeSize)
  await reopened.close()
})

test('queued prewrite fence aborts under the WAL mutex before the first new byte', async t => {
  const root = await temporaryRoot(t, 'blind-transaction-prewrite-fence')
  let enterWalFence
  let releaseWalFence
  const walFenceEntered = new Promise(resolve => { enterWalFence = resolve })
  const walFenceRelease = new Promise(resolve => { releaseWalFence = resolve })
  const store = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH,
    async faultInjector (point, context) {
      if (point === 'wal:after-sync' && context.sequence === 1n) {
        enterWalFence()
        await walFenceRelease
      }
    }
  })
  await store.open(() => {})
  const first = store.appendAndApply({
    type: 201,
    transactionId: b4a.alloc(32, 0x51),
    virtualBucket: 1,
    payload: b4a.from('first', 'ascii')
  }, () => {})
  await walFenceEntered
  const walPath = path.join(root, 'control', 'wal.v2')
  const sizeWithFirstFrame = (await fs.stat(walPath)).size
  const controller = new AbortController()
  let secondApplied = false
  const second = store.appendAndApply({
    type: 202,
    transactionId: b4a.alloc(32, 0x52),
    virtualBucket: 2,
    payload: b4a.from('second', 'ascii')
  }, () => { secondApplied = true }, {
    prewriteFence () {
      if (controller.signal.aborted) {
        const error = new Error('queued WAL append crossed its abort fence')
        error.code = 'ABORT_ERR'
        throw error
      }
    }
  })
  const secondError = second.then(() => null, error => error)
  controller.abort()
  releaseWalFence()
  t.is((await first).sequence, 1n)
  t.is((await secondError).code, 'ABORT_ERR')
  t.is(secondApplied, false)
  t.is((await fs.stat(walPath)).size, sizeWithFirstFrame,
    'queued cancellation is fenced before writing any byte of the next frame')
  t.is(store.walSequence, 1n)
  t.is(store.poisoned, false)
  await store.close()
})

test('transaction store owns runtime secrets and destroys them without retaining caller aliases', async t => {
  const root = await temporaryRoot(t, 'blind-transaction-secret-ownership')
  const partitionKey = b4a.alloc(32, 0xa1)
  const ownerFenceTokenHash = b4a.alloc(32, 0xa2)
  const durabilityContinuityHash = b4a.alloc(32, 0xa5)
  const expectedPartitionKey = b4a.from(partitionKey)
  const expectedOwnerFenceTokenHash = b4a.from(ownerFenceTokenHash)
  const expectedDurabilityContinuityHash = b4a.from(durabilityContinuityHash)
  const store = new BlindTransactionStore({
    root,
    partitionKey,
    ownerFenceTokenHash,
    durabilityContinuityHash
  })

  t.is(store.partitionKey === partitionKey, false)
  t.is(store.ownerFenceTokenHash === ownerFenceTokenHash, false)
  t.is(store.durabilityContinuityHash === durabilityContinuityHash, false)
  partitionKey.fill(0)
  ownerFenceTokenHash.fill(0)
  durabilityContinuityHash.fill(0)
  t.alike(store.partitionKey, expectedPartitionKey)
  t.alike(store.ownerFenceTokenHash, expectedOwnerFenceTokenHash)
  t.alike(store.durabilityContinuityHash, expectedDurabilityContinuityHash)

  await store.open(() => {})
  await store.append({
    type: 201,
    transactionId: b4a.alloc(32, 0xa3),
    virtualBucket: store.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, b4a.alloc(32, 0xa4)),
    payload: b4a.from('owned-secret-proof', 'ascii')
  })
  await store.close()

  t.alike(store.partitionKey, b4a.alloc(32))
  t.alike(store.ownerFenceTokenHash, b4a.alloc(32))
  t.alike(store.durabilityContinuityHash, b4a.alloc(32))
  await t.exception(store.open(() => {}), /secrets were destroyed/)
})

test('transaction close drains opaque filesystem work and every opaque operation is lifecycle guarded', async t => {
  const root = await temporaryRoot(t, 'blind-transaction-opaque-lifecycle')
  const store = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  const body = b4a.from('opaque-lifecycle-body', 'ascii')
  const stageOptions = {
    expectedLength: body.byteLength,
    expectedHash: blake2b256(body),
    deadlineUnixMillis: BigInt(Date.now() + 5000),
    source: body
  }
  await t.exception(store.stageOpaque(stageOptions), /not open/)
  await store.open(() => {})

  let enteredSource
  const sourceEntered = new Promise(resolve => { enteredSource = resolve })
  let releaseSource
  const sourceGate = new Promise(resolve => { releaseSource = resolve })
  const staging = store.stageOpaque({
    ...stageOptions,
    source: (async function * () {
      enteredSource()
      await sourceGate
      yield body
    })()
  })
  await sourceEntered

  let closed = false
  const closing = store.close().then(() => { closed = true })
  await new Promise(resolve => setImmediate(resolve))
  t.is(closed, false)
  const reference = { virtualBucket: 0, objectId: b4a.alloc(32, 0xb1) }
  for (const refused of [
    store.stageOpaque(stageOptions),
    store.publishOpaque({ token: b4a.alloc(32, 0xb2) }, 0),
    store.discardStaged({ token: b4a.alloc(32, 0xb3) }),
    store.inspectOpaque(reference, body.byteLength, stageOptions.expectedHash),
    store.removeOpaque(reference),
    store.cleanupStaging(),
    store.cleanupOrphans(new Set())
  ]) await t.exception(refused, /closing/)

  releaseSource()
  const staged = await staging
  await closing
  t.is(closed, true)
  for (const refused of [
    store.stageOpaque(stageOptions),
    store.publishOpaque(staged, 0),
    store.discardStaged(staged),
    store.inspectOpaque(reference, body.byteLength, stageOptions.expectedHash),
    store.removeOpaque(reference),
    store.cleanupStaging(),
    store.cleanupOrphans(new Set())
  ]) await t.exception(refused, /destroyed on close/)

  const reopened = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  await reopened.open(() => {})
  t.alike(await fs.readdir(path.join(root, 'staging')), [])
  await reopened.close()
})

test('cell storage owns every identity authority and destroys its copies on terminal close', async t => {
  const root = await temporaryRoot(t, 'blind-cell-identity-ownership')
  const time = clock()
  const relayPublicKey = b4a.alloc(32, 0xb1)
  const storeId = b4a.alloc(32, 0xb2)
  const partitionKey = b4a.alloc(32, 0xb3)
  const ownerFenceTokenHash = b4a.alloc(32, 0xb4)
  const durabilityContinuityHash = b4a.alloc(32, 0xb5)
  const durabilityProfileHash = b4a.alloc(32, 0xb6)
  const authorities = {
    relayPublicKey,
    storeId,
    partitionKey,
    ownerFenceTokenHash,
    durabilityContinuityHash,
    durabilityProfileHash
  }
  const expected = Object.fromEntries(Object.entries(authorities)
    .map(([field, value]) => [field, b4a.from(value)]))
  const engine = new BlindCellStorageEngine(options(root, time, authorities))

  for (const value of Object.values(authorities)) value.fill(0)
  t.alike(engine.relayPublicKey, expected.relayPublicKey)
  t.alike(engine.storeId, expected.storeId)
  t.alike(engine.durabilityContinuityHash, expected.durabilityContinuityHash)
  t.alike(engine.durabilityProfileHash, expected.durabilityProfileHash)
  t.alike(engine.transactionStore.partitionKey, expected.partitionKey)
  t.alike(engine.transactionStore.ownerFenceTokenHash, expected.ownerFenceTokenHash)
  t.alike(engine.transactionStore.durabilityContinuityHash, expected.durabilityContinuityHash)

  await engine.open()
  await engine.close()
  t.alike(engine.relayPublicKey, b4a.alloc(32))
  t.alike(engine.storeId, b4a.alloc(32))
  t.alike(engine.durabilityContinuityHash, b4a.alloc(32))
  t.alike(engine.durabilityProfileHash, b4a.alloc(32))
  t.alike(engine.transactionStore.partitionKey, b4a.alloc(32))
  t.alike(engine.transactionStore.ownerFenceTokenHash, b4a.alloc(32))
  t.alike(engine.transactionStore.durabilityContinuityHash, b4a.alloc(32))
  await t.exception(engine.open(), /identity was destroyed/)
})

test('cell PUT is durable, first-write-wins, opaque on disk, and exact retry survives restart without body work', async t => {
  const root = await temporaryRoot(t, 'blind-cell-durable')
  const time = clock()
  const fixture = putFixture()
  let engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const stored = await engine.putCell(fixture)
  t.is(stored.status, 'stored')
  t.is(stored.replay, false)
  t.is(stored.cell.stateRevision, 0n)
  t.is(stored.cell.leaseEpoch, 1004)
  const read = await engine.readCell(fixture.request.storageSlot)
  t.ok(b4a.equals(read.cellBlob, fixture.cellBlob))

  const blobPath = await findOnlyBlob(root)
  const objectName = path.basename(blobPath)
  t.is(/^[0-9a-f]{64}\.blob$/.test(objectName), true)
  t.is(objectName.includes(b4a.toString(fixture.request.storageSlot, 'hex')), false)
  t.is(objectName.includes(b4a.toString(fixture.request.declaredBlobHash, 'hex')), false)

  const noBodyRetry = {
    ...fixture,
    source: (async function * () { throw new Error('exact retry must not read a body') })()
  }
  const replay = await engine.putCell(noBodyRetry)
  t.is(replay.replay, true)
  t.ok(b4a.equals(replay.resultIdentity, stored.resultIdentity))
  const beforeRestart = engine.status()
  t.is(beforeRestart.accounting.storedBytes, 4096)
  t.is(beforeRestart.accounting.stagingBytes, 0)
  await engine.close()

  engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const afterRestart = await engine.putCell(noBodyRetry)
  t.is(afterRestart.replay, true)
  t.ok(b4a.equals((await engine.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))

  const changedNonce = putFixture({
    keys: fixture.keys,
    cellBlob: fixture.cellBlob,
    clientNonce: b4a.alloc(32, 0xb2),
    spendTag: fixture.preparedAdmission.spendTag
  })
  await rejectsCode(t, engine.putCell(changedNonce), 'SPEND_REPLAY')
  const changedSpend = putFixture({
    keys: fixture.keys,
    cellBlob: fixture.cellBlob,
    clientNonce: b4a.alloc(32, 0xb3),
    spendTag: b4a.alloc(32, 0xc2)
  })
  await rejectsCode(t, engine.putCell(changedSpend), 'CONFLICT')
  await engine.close()
})

test('daemon pins the private IPC atomic record kind to WAL type 17 and the generated store authority', async t => {
  const recordKind = PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.atomicCommitRecordKind
  const recordType = BLIND_CELL_WAL_TYPE[recordKind]
  const decoded = decodeStoreFormatAuthorityV1(await fs.readFile(STORE_FORMAT_AUTHORITY_URL))
  const rule = decoded.entries.find(entry => entry.name === 'wal.cell.put-atomic-committed')
  const protocolPackage = JSON.parse(await fs.readFile(BLIND_PROTOCOL_PACKAGE_URL, 'utf8'))

  t.is(recordKind, 'PUT_ATOMIC_COMMITTED')
  t.is(recordType, 17)
  t.is(PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.v2EmitsLegacyReservationWal, false)
  t.ok(rule)
  t.ok(rule.value.includes(`recordType=${recordType}`))
  t.ok(rule.value.includes('BlindPutAtomicCommittedStoreV1'))
  t.absent(protocolPackage.dependencies?.['@hiverelay/blind-ipc'])
})

test('recovery composes legacy Cell WAL records with one self-contained atomic type-17 commit', async t => {
  const root = await temporaryRoot(t, 'blind-cell-mixed-atomic-recovery')
  const time = clock()
  const engineOverrides = {
    storeId: STORE_ID,
    durabilityProfileHash: DURABILITY_PROFILE_HASH
  }
  const legacy = putFixture({ spendByte: 0xa1, blobByte: 0xa1 })
  const atomic = putFixture({ spendByte: 0xa2, blobByte: 0xa2 })
  let engine = new BlindCellStorageEngine(options(root, time, engineOverrides))
  await engine.open()
  await engine.putCell(legacy)
  const candidate = await atomicCommitCandidate(engine, time, atomic)
  const resultBindingBytes = candidate.payload.resultBindingBytes
  const resultIdentity = candidate.payload.resultIdentity
  await engine.transactionStore.append({
    type: BLIND_CELL_WAL_TYPE.PUT_ATOMIC_COMMITTED,
    transactionId: candidate.transactionId,
    virtualBucket: candidate.virtualBucket,
    payload: encodeCanonical(blindPutAtomicCommittedStoreV1, candidate.payload)
  })
  await engine.close()

  engine = new BlindCellStorageEngine(options(root, time, engineOverrides))
  await engine.open()
  t.alike(BLIND_CELL_WAL_TYPE, {
    INGRESS_RESERVED: 1,
    ATTEMPT_CONSUMED: 2,
    PUT_COMMITTED: 3,
    PUT_TERMINAL: 4,
    RENEW_COMMITTED: 5,
    DROP_COMMITTED: 6,
    POLICY_COMMITTED: 7,
    GC_COMMITTED: 8,
    FLOOR_ADVANCE: 9,
    CLOCK_UNSAFE: 10,
    CLOCK_CONFIRM: 11,
    COMPACT: 12,
    INTEGRITY_FAILED: 13,
    READ_PIN_COMMITTED: 14,
    READ_PIN_FINALIZED: 15,
    READ_PIN_EXPIRED: 16,
    PUT_ATOMIC_COMMITTED: 17
  })
  t.alike((await engine.readCell(legacy.request.storageSlot)).cellBlob, legacy.cellBlob)
  t.alike((await engine.readCell(atomic.request.storageSlot)).cellBlob, atomic.cellBlob)
  const replay = await engine.putCell({
    ...atomic,
    resultBinding: resultBindingBytes,
    source: (async function * () { throw new Error('atomic retry must not read a body') })()
  })
  t.is(replay.replay, true)
  t.alike(replay.resultIdentity, resultIdentity)
  const snapshot = verifyBlindCellStorageControlSnapshotState(
    await engine.captureControlSnapshotState()
  )
  const atomicSpend = snapshot.spends.get(b4a.toString(atomic.preparedAdmission.spendTag, 'hex'))
  t.is(atomicSpend.atomicCommitted, true)
  t.absent(atomicSpend.deadlineUnixMillis)
  t.absent(atomicSpend.remainingAttempts)
  t.absent(atomicSpend.reservedEpoch)
  t.is(engine.status().accounting.storedBytes, 2 * atomic.cellBlob.byteLength)
  t.is(engine.status().accounting.spends, 2)
  await engine.close()
})

for (const scenario of MALFORMED_ATOMIC_RECOVERY_CASES) {
  test(`type-17 recovery rejects ${scenario.name} without partial authority`, async t => {
    const root = await containedAtomicRecoveryRoot(t, scenario.name.replaceAll(' ', '-'))
    const time = clock(2000)
    const engineOverrides = {
      storeId: STORE_ID,
      durabilityProfileHash: DURABILITY_PROFILE_HASH
    }
    const baseline = putFixture({ spendByte: 0xa1, blobByte: 0xa1 })
    const atomic = putFixture({
      allocationEpoch: scenario.allocationEpoch == null
        ? 1000
        : scenario.allocationEpoch(time),
      spendByte: 0xa2,
      blobByte: 0xa2
    })
    let engine = new BlindCellStorageEngine(options(root, time, engineOverrides))
    await engine.open()
    if (scenario.baseline) await engine.putCell(baseline)
    const expectedState = recoveryState(engine)
    const candidate = await atomicCommitCandidate(engine, time, atomic)
    if (scenario.mutate) scenario.mutate(candidate, { atomic, baseline, engine, time })
    const orphanPath = opaqueBlobPath(root, candidate.reference)
    const orphanObjectId = b4a.from(candidate.reference.objectId)
    await engine.transactionStore.append({
      type: BLIND_CELL_WAL_TYPE.PUT_ATOMIC_COMMITTED,
      transactionId: candidate.transactionId,
      virtualBucket: candidate.virtualBucket,
      payload: encodeCanonical(blindPutAtomicCommittedStoreV1, candidate.payload)
    })
    await engine.close()
    if (scenario.zeroTransactionId) await zeroLastWalTransactionId(root)

    engine = new BlindCellStorageEngine(options(root, time, engineOverrides))
    let failure = null
    try {
      await engine.open()
    } catch (error) {
      failure = error
    }
    if (failure == null) {
      await engine.close()
      t.fail(`${scenario.name} unexpectedly recovered`)
      return
    }

    t.ok(failure instanceof BlindWalIntegrityError)
    t.ok(scenario.error.test(failure.message), `${scenario.name}: ${failure.message}`)
    t.is(engine.opened, false)
    t.is(engine.transactionStore.opened, false)
    t.is(engine.transactionStore.handle, null)
    t.is(engine.transactionStore.storeLockHandle, null)
    t.alike(recoveryState(engine), expectedState)
    t.absent([...engine.cells.values()].some(record =>
      b4a.equals(record.blobReference.objectId, orphanObjectId)))
    t.alike(await fs.readFile(orphanPath), atomic.cellBlob,
      'published bytes remain a physical orphan, never recovered blob authority')
    t.exception(() => engine.status(), /cell storage engine is not open/)
    await t.exception(
      Promise.resolve().then(() => engine.readCell(atomic.request.storageSlot)),
      /cell storage engine is not open/
    )
  })
}

test('concurrent identical PUT consumes one spend and publishes one cell', async t => {
  const root = await temporaryRoot(t, 'blind-cell-concurrent')
  const time = clock()
  const fixture = putFixture()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const outcomes = await Promise.allSettled([
    engine.putCell({ ...fixture, source: b4a.from(fixture.cellBlob) }),
    engine.putCell({ ...fixture, source: b4a.from(fixture.cellBlob) })
  ])
  const stored = outcomes.find(outcome => outcome.status === 'fulfilled').value
  const busy = outcomes.find(outcome => outcome.status === 'rejected').reason
  t.is(stored.replay, false)
  t.is(busy.code, 'BUSY')
  const replay = await engine.putCell(fixture)
  t.is(replay.replay, true)
  t.ok(b4a.equals(stored.resultIdentity, replay.resultIdentity))
  t.is(engine.status().accounting.spends, 1)
  t.is(engine.status().accounting.cellRecords, 1)
  t.is((await fs.readdir(path.dirname(await findOnlyBlob(root)))).length, 1)
  await engine.close()
})

test('ingress has two crash-persistent attempt credits and invalid complete bodies become terminal', async t => {
  const root = await temporaryRoot(t, 'blind-cell-attempts')
  const time = clock()
  const fixture = putFixture()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const interrupted = {
    ...fixture,
    source: (async function * () {
      yield fixture.cellBlob.subarray(0, 1024)
      throw new Error('transport reset')
    })()
  }
  const firstError = await rejectsCode(t, engine.putCell(interrupted), 'BUSY')
  t.is(firstError.retryable, true)
  t.is(engine.status().accounting.stagingBytes, 4096)
  const stored = await engine.putCell(fixture)
  t.is(stored.replay, false)
  t.is(engine.status().accounting.stagingBytes, 0)
  await engine.close()

  const terminalRoot = await temporaryRoot(t, 'blind-cell-terminal')
  const wrongHash = b4a.alloc(32, 0x55)
  const invalid = putFixture({ declaredBlobHash: wrongHash, spendByte: 0xc3 })
  const terminal = new BlindCellStorageEngine(options(terminalRoot, time))
  await terminal.open()
  await rejectsCode(t, terminal.putCell(invalid), 'RETRY_TERMINAL')
  t.is(terminal.status().accounting.stagingBytes, 0)
  await rejectsCode(t, terminal.putCell(invalid), 'RETRY_TERMINAL')
  t.is(terminal.status().accounting.spends, 1)
  t.is(terminal.status().accounting.cellRecords, 0)
  await terminal.close()
})

test('staging and metadata quotas reject before reading another opaque body', async t => {
  const root = await temporaryRoot(t, 'blind-cell-quota')
  const time = clock()
  const first = putFixture({ spendByte: 0x61 })
  const second = putFixture({ spendByte: 0x62, blobByte: 0x62 })
  let secondBodyRead = false
  second.source = (async function * () {
    secondBodyRead = true
    throw new Error('must not run')
  })()
  const engine = new BlindCellStorageEngine(options(root, time, {
    maxStoredBytes: 4096,
    maxStagingBytes: 4096,
    maxStagingBytesPerProfile: 4096,
    maxControlBytes: 1024,
    maxTombstoneBytes: 1024
  }))
  await engine.open()
  await rejectsCode(t, engine.putCell({
    ...first,
    source: (async function * () { throw new Error('first interrupted') })()
  }), 'BUSY')
  await rejectsCode(t, engine.putCell(second), 'BUSY')
  t.is(secondBodyRead, false)
  t.is(engine.status().accounting.stagingBytes, 4096)
  await engine.close()
})

test('suppression is independent from owner renew/drop and exact management retries are stable', async t => {
  const root = await temporaryRoot(t, 'blind-cell-lifecycle')
  const time = clock()
  const fixture = putFixture()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const stored = await engine.putCell(fixture)
  const suppressed = await engine.setPolicy(fixture.request.storageSlot, 0n, true)
  t.is(suppressed.policyState, 'SUPPRESSED')
  t.is(suppressed.stateRevision, 0n)
  await rejectsCode(t, engine.readCell(fixture.request.storageSlot), 'NOT_FOUND')

  const renewal = renewRequest(fixture, stored.cell, time)
  const notDue = await rejectsCode(t, engine.renewCell(renewal), 'RENEW_NOT_DUE')
  t.is(notDue.retryAfterEpoch, 1001)

  time.epoch = 1004
  await engine.refreshClock()
  const renewed = await engine.renewCell(renewal)
  t.is(renewed.cell.stateRevision, 1n)
  t.is(renewed.cell.policyState, 'SUPPRESSED')
  t.is(renewed.cell.leaseEpoch, 1008)
  await rejectsCode(t, engine.renewCell(renewal), 'RETRY_TERMINAL')

  const restored = await engine.setPolicy(fixture.request.storageSlot, 1n, false)
  t.is(restored.policyState, 'VISIBLE')
  const renewalReplay = await engine.renewCell(renewal)
  t.is(renewalReplay.replay, true)
  t.ok(b4a.equals(renewalReplay.resultIdentity, renewed.resultIdentity))
  t.ok(b4a.equals((await engine.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))
  const drop = dropRequest(fixture, restored)
  const dropped = await engine.dropCell(drop)
  t.is(dropped.cell.objectState, 'TOMBSTONE')
  await rejectsCode(t, engine.readCell(fixture.request.storageSlot), 'NOT_FOUND')
  const dropReplay = await engine.dropCell(drop)
  t.is(dropReplay.replay, true)
  t.ok(b4a.equals(dropReplay.resultIdentity, dropped.resultIdentity))
  await rejectsCode(t, engine.renewCell(renewal), 'RETRY_TERMINAL')
  await engine.close()
})

test('confirmed expiry GC never resurrects and 1460-epoch metadata horizon is enforced', async t => {
  const root = await temporaryRoot(t, 'blind-cell-gc')
  const time = clock()
  const fixture = putFixture()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  time.epoch = 1009
  await engine.confirmClock(time.epoch)
  t.is(await engine.gc(), 1)
  await rejectsCode(t, engine.readCell(fixture.request.storageSlot), 'NOT_FOUND')
  t.is(engine.status().accounting.storedBytes, 0)
  t.is(await engine.compact(), 0)

  time.epoch = 2470
  await engine.confirmClock(time.epoch)
  t.is(await engine.compact(), 2)
  t.is(engine.status().accounting.cellRecords, 0)
  t.is(engine.status().accounting.spends, 0)
  await engine.close()

  const reopened = new BlindCellStorageEngine(options(root, time))
  await reopened.open()
  t.is(reopened.status().accounting.cellRecords, 0)
  t.is(reopened.status().accounting.spends, 0)
  await reopened.close()
})

test('clock jumps and rollback fail lease mutation closed while existing visible bytes remain readable', async t => {
  const root = await temporaryRoot(t, 'blind-cell-clock')
  const time = clock()
  const fixture = putFixture()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  time.epoch = 1005
  t.is((await engine.refreshClock()).state, 'CLOCK_UNSAFE')
  t.ok(b4a.equals((await engine.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))
  const other = putFixture({ spendByte: 0x72, blobByte: 0x72, allocationEpoch: 1005 })
  await rejectsCode(t, engine.putCell(other), 'BUSY')
  await engine.confirmClock(1005)
  t.is(engine.status().state, 'READY')
  t.ok(b4a.equals((await engine.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))
  time.epoch = 999
  t.is((await engine.refreshClock()).state, 'CLOCK_UNSAFE')
  t.is(engine.status().epochFloor, 1005)
  await engine.close()
})

test('scrub emits opaque repair evidence, persists read-only state, and forbids same-identity repair', async t => {
  const root = await temporaryRoot(t, 'blind-cell-scrub')
  const time = clock()
  const fixture = putFixture()
  let engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  const blobPath = await findOnlyBlob(root)
  const corrupted = await fs.readFile(blobPath)
  corrupted[100] ^= 0xff
  await fs.writeFile(blobPath, corrupted)
  const evidence = await engine.scrub({ limit: 16 })
  t.is(evidence.state, 'RECOVERY_GAP_READ_ONLY')
  t.is(evidence.failureCount, 1)
  t.is(evidence.failures[0].reason, 3)
  t.is(b4a.equals(evidence.failures[0].locatorCommitment, fixture.request.storageSlot), false)
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  t.exception(() => engine.repairUnderSameIdentity(), BlindCellStorageError)
  await rejectsCode(t, engine.putCell(putFixture({ spendByte: 0x82, blobByte: 0x82 })), 'INTERNAL')
  const failedSequence = engine.status().walSequence
  await engine.close()

  engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  t.is(engine.status().walSequence, failedSequence)
  await engine.close()
})

test('interior WAL corruption, writer-fence drift, and durability-continuity drift fail recovery closed', async t => {
  const root = await temporaryRoot(t, 'blind-cell-wal-corrupt')
  const time = clock()
  const fixture = putFixture()
  let engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  await engine.close()
  const walPath = path.join(root, 'control', 'wal.v2')
  const wal = await fs.readFile(walPath)
  wal[100] ^= 0xff
  await fs.writeFile(walPath, wal)
  engine = new BlindCellStorageEngine(options(root, time))
  await t.exception(engine.open(), BlindWalIntegrityError)

  const fenceRoot = await temporaryRoot(t, 'blind-cell-fence')
  const clean = new BlindCellStorageEngine(options(fenceRoot, time))
  await clean.open()
  await clean.putCell(putFixture({ spendByte: 0x91, blobByte: 0x91 }))
  await clean.close()
  const wrongFence = new BlindCellStorageEngine(options(fenceRoot, time, { ownerFenceTokenHash: b4a.alloc(32, 0x92) }))
  await t.exception(wrongFence.open(), /writer fence/)

  const continuityRoot = await temporaryRoot(t, 'blind-cell-continuity')
  const continuity = new BlindCellStorageEngine(options(continuityRoot, time))
  await continuity.open()
  await continuity.putCell(putFixture({ spendByte: 0x92, blobByte: 0x92 }))
  await continuity.close()
  const wrongContinuity = new BlindCellStorageEngine(options(continuityRoot, time, {
    durabilityContinuityHash: b4a.alloc(32, 0x95)
  }))
  await t.exception(wrongContinuity.open(), /durability continuity/)
})

test('one MiB byte sources are internally sliced and stalled sources expire terminally', async t => {
  const root = await temporaryRoot(t, 'blind-cell-large')
  const time = clock()
  const largeBlob = b4a.alloc(1024 * 1024, 0x6a)
  const large = putFixture({ sizeClass: 5, cellBlob: largeBlob, spendByte: 0x6a })
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const stored = await engine.putCell(large)
  t.is(stored.cell.sizeClass, 5)
  t.ok(b4a.equals((await engine.readCell(large.request.storageSlot)).cellBlob, largeBlob))
  await engine.close()

  const stallRoot = await temporaryRoot(t, 'blind-cell-stall')
  const stalled = putFixture({ spendByte: 0x6b, blobByte: 0x6b })
  stalled.source = { [Symbol.asyncIterator] () { return this }, next () { return new Promise(() => {}) } }
  const bounded = new BlindCellStorageEngine(options(stallRoot, time, { reservationMillis: 20 }))
  await bounded.open()
  const started = Date.now()
  await rejectsCode(t, bounded.putCell(stalled), 'RETRY_TERMINAL')
  t.ok(Date.now() - started < 1000)
  t.is(bounded.status().accounting.stagingBytes, 0)
  t.is(bounded.status().accounting.reservedCells, 0)
  await bounded.close()
})

test('restart sweeps expired reservations and active reservations count against maxCells', async t => {
  const root = await temporaryRoot(t, 'blind-cell-reservation-sweep')
  const time = clock()
  const first = putFixture({ spendByte: 0x73, blobByte: 0x73 })
  let engine = new BlindCellStorageEngine(options(root, time, {
    maxCells: 1,
    reservationMillis: 20
  }))
  await engine.open()
  await rejectsCode(t, engine.putCell({
    ...first,
    source: (async function * () { throw new Error('interrupted once') })()
  }), 'BUSY')
  t.is(engine.status().accounting.reservedCells, 1)
  await rejectsCode(t, engine.putCell(putFixture({ spendByte: 0x74, blobByte: 0x74 })), 'BUSY')
  await engine.close()

  time.offsetMillis = 21n
  engine = new BlindCellStorageEngine(options(root, time, {
    maxCells: 1,
    reservationMillis: 20
  }))
  await engine.open()
  t.is(engine.status().accounting.reservedCells, 0)
  t.is(engine.status().accounting.stagingBytes, 0)
  await rejectsCode(t, engine.putCell(first), 'RETRY_TERMINAL')
  await engine.close()
})

test('store roots, files and staging tokens fail closed on path substitution', async t => {
  const base = await temporaryRoot(t, 'blind-cell-path-hardening')
  const time = clock()
  const realRoot = path.join(base, 'real')
  const linkedRoot = path.join(base, 'linked')
  await fs.mkdir(realRoot, { mode: 0o700 })
  await fs.symlink(realRoot, linkedRoot)
  const linked = new BlindCellStorageEngine(options(linkedRoot, time))
  await t.exception(linked.open(), /symlink|realpath/)

  const weakRoot = path.join(base, 'weak')
  await fs.mkdir(weakRoot, { mode: 0o700 })
  await fs.chmod(weakRoot, 0o755)
  const weak = new BlindCellStorageEngine(options(weakRoot, time))
  await t.exception(weak.open(), /private owner-only mode/)

  const tokenRoot = path.join(base, 'token')
  await fs.mkdir(tokenRoot, { mode: 0o700 })
  const store = new BlindTransactionStore({
    root: tokenRoot,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  await store.open(() => {})
  const competing = new BlindTransactionStore({
    root: tokenRoot,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: DURABILITY_CONTINUITY_HASH
  })
  await t.exception(competing.open(() => {}), /active writer/)
  await t.exception(store.publishOpaque({ token: b4a.alloc(32, 0x99) }, 1), /unknown, forged, or already consumed/)
  await store.close()
  await competing.open(() => {})
  await competing.close()
})

test('single-inode read detection persists recovery-gap state before returning generic absence', async t => {
  const root = await temporaryRoot(t, 'blind-cell-read-integrity')
  const time = clock()
  const fixture = putFixture({ spendByte: 0x83 })
  let engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  const blobPath = await findOnlyBlob(root)
  const original = await fs.readFile(blobPath)
  const substitute = path.join(root, 'substitute.bin')
  await fs.writeFile(substitute, original, { mode: 0o600 })
  await fs.unlink(blobPath)
  await fs.symlink(substitute, blobPath)
  await rejectsCode(t, engine.readCell(fixture.request.storageSlot), 'NOT_FOUND')
  const failedSequence = engine.status().walSequence
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  await engine.close()

  await fs.unlink(blobPath)
  await fs.writeFile(blobPath, original, { mode: 0o600 })
  engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  t.is(engine.status().walSequence, failedSequence)
  await engine.close()
})

test('startup remains read-only when full body scrub finds silent same-size corruption', async t => {
  const root = await temporaryRoot(t, 'blind-cell-startup-scrub')
  const time = clock()
  const fixture = putFixture({ spendByte: 0x88 })
  let engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await engine.putCell(fixture)
  const blobPath = await findOnlyBlob(root)
  await engine.close()
  const corrupted = await fs.readFile(blobPath)
  corrupted[corrupted.byteLength - 1] ^= 0xff
  await fs.writeFile(blobPath, corrupted, { mode: 0o600 })
  engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  t.is(engine.status().state, 'READ_ONLY')
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  await rejectsCode(t, engine.putCell(putFixture({ spendByte: 0x89 })), 'INTERNAL')
  await engine.close()
})

test('open failure releases lifecycle ownership and close drains an admitted body write', async t => {
  const root = await temporaryRoot(t, 'blind-cell-open-lifecycle')
  const time = clock()
  let tripped = false
  const failed = new BlindCellStorageEngine(options(root, time, {
    faultInjector (point, context) {
      if (!tripped && point === 'wal:after-sync' && context.sequence === 1n) {
        tripped = true
        throw new Error('crash after genesis floor fsync')
      }
    }
  }))
  await t.exception(failed.open(), /crash after genesis/)
  const recovered = new BlindCellStorageEngine(options(root, time))
  await recovered.open()
  await recovered.close()

  const drainRoot = await temporaryRoot(t, 'blind-cell-close-drain')
  const fixture = putFixture({ spendByte: 0x84 })
  fixture.source = (async function * () {
    await new Promise(resolve => setTimeout(resolve, 20))
    yield fixture.cellBlob
  })()
  const draining = new BlindCellStorageEngine(options(drainRoot, time))
  await draining.open()
  const write = draining.putCell(fixture)
  await new Promise(resolve => setImmediate(resolve))
  const close = draining.close()
  const stored = await write
  await close
  t.is(stored.status, 'stored')
  const reopened = new BlindCellStorageEngine(options(drainRoot, time))
  await reopened.open()
  t.ok(b4a.equals((await reopened.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))
  await reopened.close()
})

test('post-publish and post-final-fsync crashes recover without duplicate mutation or committed-blob deletion', async t => {
  const publishRoot = await temporaryRoot(t, 'blind-cell-publish-crash')
  const time = clock()
  const publishedFixture = putFixture({ spendByte: 0x85 })
  let failedPublish = false
  let engine = new BlindCellStorageEngine(options(publishRoot, time, {
    faultInjector (point) {
      if (!failedPublish && point === 'body:after-publish') {
        failedPublish = true
        throw new Error('crash after opaque publish')
      }
    }
  }))
  await engine.open()
  await t.exception(engine.putCell(publishedFixture), /crash after opaque publish/)
  await engine.close()
  engine = new BlindCellStorageEngine(options(publishRoot, time))
  await engine.open()
  const storedAfterOrphan = await engine.putCell(publishedFixture)
  t.is(storedAfterOrphan.replay, false)
  await engine.close()

  const fsyncRoot = await temporaryRoot(t, 'blind-cell-final-fsync-crash')
  const fsyncedFixture = putFixture({ spendByte: 0x86 })
  engine = new BlindCellStorageEngine(options(fsyncRoot, time, {
    faultInjector (point, context) {
      if (point === 'wal:after-sync' && context.sequence === 4n) {
        throw new Error('crash after final WAL fsync')
      }
    }
  }))
  await engine.open()
  await t.exception(engine.putCell(fsyncedFixture), /crash after final WAL fsync/)
  await engine.close()
  engine = new BlindCellStorageEngine(options(fsyncRoot, time))
  await engine.open()
  const replay = await engine.putCell({
    ...fsyncedFixture,
    source: (async function * () { throw new Error('must not re-read committed bytes') })()
  })
  t.is(replay.replay, true)
  t.ok(b4a.equals((await engine.readCell(fsyncedFixture.request.storageSlot)).cellBlob, fsyncedFixture.cellBlob))
  t.is(engine.status().accounting.spends, 1)
  t.is(engine.status().accounting.cellRecords, 1)
  await engine.close()
})

test('aborted PUT after final stage fsync starts no publish or committed spend', async t => {
  const root = await temporaryRoot(t, 'blind-cell-abort-fence')
  const time = clock()
  let enterFsyncFence
  let releaseFsyncFence
  const fsyncFenceEntered = new Promise(resolve => { enterFsyncFence = resolve })
  const fsyncFenceRelease = new Promise(resolve => { releaseFsyncFence = resolve })
  const controller = new AbortController()
  const fixture = putFixture({ spendByte: 0x8a })
  fixture.signal = controller.signal
  const engine = new BlindCellStorageEngine(options(root, time, {
    async faultInjector (point) {
      if (point === 'body:after-fsync') {
        enterFsyncFence()
        await fsyncFenceRelease
      }
    }
  }))
  await engine.open()
  let publishCalls = 0
  const publishOpaque = engine.transactionStore.publishOpaque.bind(engine.transactionStore)
  engine.transactionStore.publishOpaque = (...args) => {
    publishCalls++
    return publishOpaque(...args)
  }
  const pending = engine.putCell(fixture)
  const rejected = pending.then(() => null, error => error)
  await fsyncFenceEntered
  controller.abort()
  releaseFsyncFence()
  const error = await rejected
  t.is(error.code, 'BUSY')
  t.is(publishCalls, 0, 'abort fence prevents the irreversible publish from starting')
  t.is(engine.status().accounting.cellRecords, 0)
  t.is(engine.status().accounting.storedBytes, 0)
  t.is([...engine.spends.values()].some(entry => entry.status === 'committed'), false,
    'abort fence leaves no committed spend')
  await engine.close()
})

test('abort after opaque publish cannot interrupt PUT_COMMITTED or poison recovery', async t => {
  const root = await temporaryRoot(t, 'blind-cell-post-publish-abort')
  const time = clock()
  const controller = new AbortController()
  const fixture = putFixture({ spendByte: 0x8b })
  fixture.signal = controller.signal
  let publishFenceCalls = 0
  let engine = new BlindCellStorageEngine(options(root, time, {
    faultInjector (point) {
      if (point === 'body:after-publish') {
        publishFenceCalls++
        controller.abort()
      }
    }
  }))
  await engine.open()
  const stored = await engine.putCell(fixture)
  t.is(stored.status, 'stored')
  t.is(publishFenceCalls, 1)
  t.is(controller.signal.aborted, true)
  t.is(engine.status().readOnlyReason, null,
    'external cancellation after publish cannot poison the live store')
  t.is(engine.status().accounting.cellRecords, 1)
  t.is([...engine.spends.values()].some(entry => entry.status === 'committed'), true)
  await engine.close()

  engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const replay = await engine.putCell({
    ...fixture,
    signal: undefined,
    source: (async function * () { throw new Error('committed replay must not read bytes') })()
  })
  t.is(replay.replay, true)
  t.is(engine.status().readOnlyReason, null)
  t.ok(b4a.equals((await engine.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob))
  await engine.close()
})

test('u32 lease exhaustion fails before spend reservation or body work', async t => {
  const root = await temporaryRoot(t, 'blind-cell-lease-overflow')
  const time = clock(0xffffffff)
  let bodyRead = false
  const fixture = putFixture({ allocationEpoch: 0xffffffff, spendByte: 0x87 })
  fixture.source = (async function * () {
    bodyRead = true
    yield fixture.cellBlob
  })()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  await rejectsCode(t, engine.putCell(fixture), 'BUSY')
  t.is(bodyRead, false)
  t.is(engine.status().accounting.spends, 0)
  t.is(engine.status().accounting.reservedCells, 0)
  await engine.close()
})

test('profile 2 and final continuity claims fail closed instead of silently degrading', async t => {
  const root = await temporaryRoot(t, 'blind-cell-profile2')
  const time = clock()
  t.exception(() => new BlindCellStorageEngine(options(root, time, { durabilityProfileId: 2 })), /profile 2/)
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const status = engine.status()
  t.ok(status.blockers.includes('FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED'))
  t.ok(status.blockers.includes('PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNIMPLEMENTED'))
  t.absent(status.blockers.find(value => value === 'EXCLUSIVE_OS_STORE_LOCK_UNIMPLEMENTED'))
  await engine.close()
})
