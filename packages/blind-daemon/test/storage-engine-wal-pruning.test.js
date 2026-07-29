import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import { generateKeyPairSync, sign } from 'node:crypto'
import b4a from 'b4a'
import {
  allocationCommitment,
  blake2b256,
  cellPutRequestCommitment,
  cellStorageSlot,
  encodeCanonical,
  relayResultBindingV1
} from '@hiverelay/blind-protocol'
import { BlindCellStorageEngine } from '../storage-engine.js'
import { BlindTransactionStore } from '../transaction-store.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const EPOCH_MILLIS = 21600000n
const RELAY_PUBLIC_KEY = b4a.alloc(32, 0x71)
const PARTITION_KEY = b4a.alloc(32, 0x81)
const FENCE_HASH = b4a.alloc(32, 0x91)
const CONTINUITY = b4a.alloc(32, 0x94)
const STORE_ID = b4a.alloc(32, 0x95)
const DURABILITY_PROFILE_HASH = b4a.alloc(32, 0x96)
const SEGMENT_MAX_BYTES = 64 * 1024
const MAX_U64 = (1n << 64n) - 1n

async function temporaryRoot (t, name = 'hiverelay-wal-pruning-') {
  const root = await createBlindBoundaryScratch(name)
  t.teardown(async () => removeBlindBoundaryScratch(root))
  return root
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
    storeId: STORE_ID,
    durabilityProfileHash: DURABILITY_PROFILE_HASH,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileId: 1,
    initialEpochFloor: time.epoch,
    nowUnixMillis: () => time.now(),
    autoClock: false,
    walSegmentMaxBytes: SEGMENT_MAX_BYTES,
    ...overrides
  }
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

function profile1ResultBindingBytes (overrides = {}) {
  return encodeCanonical(relayResultBindingV1, {
    version: 1,
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x97),
    durabilityProfileId: 1,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileHash: DURABILITY_PROFILE_HASH,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null,
    ...overrides
  })
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

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

async function atomicPut (engine, fixture) {
  return engine.commitAtomicCellPut({
    authority: await engine.stageAtomicCellPut({
      request: fixture.request,
      source: fixture.cellBlob,
      admissionProfileId: fixture.preparedAdmission.profileId,
      resultBinding: profile1ResultBindingBytes()
    }),
    preparedAdmission: fixture.preparedAdmission,
    preCommitFence: () => true
  })
}

async function sealedSegmentNames (root) {
  const names = await fs.readdir(path.join(root, 'control'))
  return names.filter(name => name.startsWith('wal-')).sort()
}

test('spent-marker horizon: pruning keeps terminal markers and SPEND_REPLAY survives an anchored reopen', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()

  // spend 1 goes terminally wrong on its first body attempt: the staged
  // bytes hash below its declared hash, so the reservation commits a
  // PUT_TERMINAL marker instead of a cell.
  const badBody = putFixture({ spendByte: 0xd1, blobByte: 0xd1, declaredBlobHash: b4a.alloc(32, 0xee) })
  const reserveSequence = engine.status().walSequence + 1n
  await rejectsCode(t, engine.putCell(badBody), 'RETRY_TERMINAL')
  const terminalSequence = engine.status().walSequence
  t.ok(terminalSequence > reserveSequence, 'reservation and terminal marker committed')

  const fixtures = []
  for (let index = 0; index < 80; index++) {
    const fixture = putFixture({ spendByte: 0x30 + index, blobByte: 0x30 + index, nonceByte: 0x60 + index })
    fixtures.push(fixture)
    const stored = await atomicPut(engine, fixture)
    t.is(stored.status, 'stored')
  }
  const sealed = await sealedSegmentNames(root)
  t.ok(sealed.length >= 1, `WAL rolled into sealed segments (${sealed.length})`)

  const floor = engine.spendRetentionWalFloorSequence()
  t.is(floor, reserveSequence, 'the floor is the oldest live spend reservation')
  const anchor = {
    sequence: engine.transactionStore.walSequence,
    hash: b4a.from(engine.transactionStore.walHash)
  }
  const pruned = await engine.transactionStore.pruneWalSegments({
    checkpointAnchor: anchor,
    retainFromSequence: floor
  })
  t.alike(pruned.prunedSegments, [], 'the horizon blocks every prune while markers are live')
  t.alike(await sealedSegmentNames(root), sealed, 'terminal marker segments survive on disk')
  await engine.close()

  const reopened = new BlindCellStorageEngine(options(root, time, { checkpointAnchor: anchor }))
  await reopened.open()
  t.is(reopened.spendRetentionWalFloorSequence(), floor, 'the floor itself is recoverable')
  await rejectsCode(t, reopened.putCell(badBody), 'RETRY_TERMINAL',
    'the terminal marker still classifies the late retry')
  const changedNonce = putFixture({
    keys: fixtures[0].keys,
    cellBlob: fixtures[0].cellBlob,
    clientNonce: b4a.alloc(32, 0xfb),
    spendTag: fixtures[0].preparedAdmission.spendTag
  })
  await rejectsCode(t, reopened.commitAtomicCellPut({
    authority: await reopened.stageAtomicCellPut({
      request: changedNonce.request,
      source: changedNonce.cellBlob,
      admissionProfileId: changedNonce.preparedAdmission.profileId,
      resultBinding: profile1ResultBindingBytes()
    }),
    preparedAdmission: changedNonce.preparedAdmission,
    preCommitFence: () => true
  }), 'SPEND_REPLAY')
  t.alike((await reopened.readCell(fixtures[0].request.storageSlot)).cellBlob, fixtures[0].cellBlob)
  await reopened.close()
})

test('compaction advances the floor and opens the legal prune window by construction', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()

  const badBody = putFixture({ spendByte: 0xd2, blobByte: 0xd2, declaredBlobHash: b4a.alloc(32, 0xed) })
  await rejectsCode(t, engine.putCell(badBody), 'RETRY_TERMINAL')
  for (let index = 0; index < 80; index++) {
    await atomicPut(engine, putFixture({ spendByte: 0x40 + index, blobByte: 0x40 + index, nonceByte: 0x70 + index }))
  }
  const sealed = await sealedSegmentNames(root)
  t.ok(sealed.length >= 1, 'WAL rolled into sealed segments')

  time.epoch = 1000 + 1461
  await engine.confirmClock(time.epoch)
  const compacted = await engine.compact()
  t.ok(compacted >= 1, 'past-horizon spends compacted away')
  t.is(engine.status().accounting.spends, 0)
  const highWater = engine.compactionWalHighWaterSequence()
  t.ok(highWater > 0n, 'the compaction high-water tracks the COMPACT frames')
  t.is(engine.spendRetentionWalFloorSequence(), MAX_U64, 'no live spend keeps the floor')

  const anchor = {
    sequence: engine.transactionStore.walSequence,
    hash: b4a.from(engine.transactionStore.walHash)
  }
  const pruned = await engine.transactionStore.pruneWalSegments({
    checkpointAnchor: anchor,
    retainFromSequence: engine.spendRetentionWalFloorSequence()
  })
  t.alike(pruned.prunedSegments.map(segment => segment.name), sealed,
    'every sealed segment is past the horizon and covered: all prune')
  t.alike(await sealedSegmentNames(root), [])
  t.ok(anchor.sequence >= highWater, 'the pruned prefix ends beyond the compaction high-water')

  // Post-prune appends chain onto the anchor boundary.
  const fixture = putFixture({ spendByte: 0xf1, blobByte: 0xf1, nonceByte: 0xf1, allocationEpoch: time.epoch })
  const stored = await atomicPut(engine, fixture)
  t.is(stored.status, 'stored')
  await engine.close()

  // The engine itself restores pre-anchor state from checkpoint snapshots
  // (not yet wired); the WAL side of the boundary replays standalone.
  const store = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY,
    walSegmentMaxBytes: SEGMENT_MAX_BYTES
  })
  const replayed = []
  await store.open(frame => replayed.push(frame), { checkpointAnchor: anchor })
  t.alike(replayed.map(frame => Number(frame.sequence)), [Number(anchor.sequence) + 1])
  t.is(replayed[0].type, 17, 'the post-anchor atomic PUT frame chains to the pruned prefix')
  await store.close()
})

test('atomic PUT commits across a segment rollover with type-17 frames on both sides', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const engine = new BlindCellStorageEngine(options(root, time))
  await engine.open()
  const fixtures = []
  for (let index = 0; index < 80; index++) {
    const fixture = putFixture({ spendByte: 0x50 + index, blobByte: 0x50 + index, nonceByte: 0x80 + index })
    fixtures.push(fixture)
    const stored = await atomicPut(engine, fixture)
    t.is(stored.status, 'stored')
  }
  const sealed = await sealedSegmentNames(root)
  t.ok(sealed.length >= 1, `WAL rolled into sealed segments (${sealed.length})`)
  const sealedLast = BigInt(`0x${sealed[sealed.length - 1].split('-')[2].slice(0, 16)}`)
  await engine.close()

  const store = new BlindTransactionStore({
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY,
    walSegmentMaxBytes: SEGMENT_MAX_BYTES
  })
  const frames = []
  await store.open(frame => frames.push(frame))
  t.ok(frames.some(frame => frame.type === 17 && frame.sequence <= sealedLast),
    'type-17 atomic commits inside the sealed segment')
  t.ok(frames.some(frame => frame.type === 17 && frame.sequence > sealedLast),
    'type-17 atomic commits continue in the live segment')
  for (let index = 1; index < frames.length; index++) {
    t.ok(b4a.equals(frames[index].previousWalHash, frames[index - 1].walHash),
      `chain continuous at frame ${frames[index].sequence}`)
  }
  await store.close()

  const reopened = new BlindCellStorageEngine(options(root, time))
  await reopened.open()
  for (const fixture of [fixtures[0], fixtures[fixtures.length - 1]]) {
    t.alike((await reopened.readCell(fixture.request.storageSlot)).cellBlob, fixture.cellBlob)
  }
  await reopened.close()
})
