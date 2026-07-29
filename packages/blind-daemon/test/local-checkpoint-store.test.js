import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  blindControlStateSnapshotV1,
  blindLocalCheckpointV1,
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  controlSnapshotHash,
  decodeCanonical,
  encodeCanonical,
  localCheckpointHash
} from '@hiverelay/blind-protocol'
import {
  BlindLocalCheckpointStore,
  createUnsafeTestOnlyBlindLocalCheckpointStore
} from '../local-checkpoint-store.js'
import { TwoSlotManifestStore } from '../manifest-store.js'
import { BlindStoreSession } from '../store-session.js'
import { BlindTransactionStore } from '../transaction-store.js'
import {
  descriptorValue,
  manifestBytes
} from './coordinator-fixtures.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const MANIFEST_KEY = b4a.alloc(32, 0x91)

function bytes (length, fill) {
  return b4a.alloc(length, fill)
}

function expectedBindings (manifest) {
  return {
    relayPublicKey: manifest.relayPublicKey,
    storeId: manifest.storeId,
    durabilityProfileId: manifest.durabilityProfileId,
    durabilityContinuityHash: manifest.durabilityContinuityHash,
    durabilityProfileHash: manifest.durabilityProfileHash,
    formatMajor: manifest.formatMajor,
    formatMinor: manifest.formatMinor,
    storeFormatHash: manifest.storeFormatHash,
    specHash: manifest.specHash,
    abiHash: manifest.abiHash,
    mapGeneration: manifest.mapGeneration,
    bucketMapHash: manifest.bucketMapHash,
    writerEpoch: manifest.writerEpoch,
    writerFenceTokenHash: manifest.writerFenceTokenHash
  }
}

function transactionOptions (root, manifest, storeSessionContext = null) {
  return {
    root,
    partitionKey: bytes(32, 0x71),
    mapGeneration: manifest.mapGeneration,
    ownerFenceTokenHash: manifest.writerFenceTokenHash,
    durabilityContinuityHash: manifest.durabilityContinuityHash,
    ...(storeSessionContext == null ? {} : { storeSessionContext })
  }
}

function snapshotValue (manifest, sequence, hash, fill) {
  return {
    version: 1,
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    storeId: b4a.from(manifest.storeId),
    durabilityContinuityHash: b4a.from(manifest.durabilityContinuityHash),
    walSequence: sequence,
    walHash: b4a.from(hash),
    entries: [
      { entryKind: 1, key: b4a.from([fill]), value: b4a.from(`state-${fill}`) },
      { entryKind: 8, key: b4a.from([fill]), value: b4a.alloc(0) }
    ]
  }
}

function checkpointValue (manifest, snapshotBytes, walAnchor, overrides = {}) {
  return {
    magic: b4a.from('HRBCKP01', 'ascii'),
    checkpointVersion: 1,
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    storeId: b4a.from(manifest.storeId),
    durabilityProfileId: manifest.durabilityProfileId,
    durabilityContinuityHash: b4a.from(manifest.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(manifest.durabilityProfileHash),
    formatMajor: manifest.formatMajor,
    formatMinor: manifest.formatMinor,
    storeFormatHash: b4a.from(manifest.storeFormatHash),
    specHash: b4a.from(manifest.specHash),
    abiHash: b4a.from(manifest.abiHash),
    mapGeneration: manifest.mapGeneration,
    bucketMapHash: b4a.from(manifest.bucketMapHash),
    writerEpoch: manifest.writerEpoch,
    writerFenceTokenHash: b4a.from(manifest.writerFenceTokenHash),
    checkpointRevision: 1n,
    previousCheckpointHash: null,
    coveredWalSequence: walAnchor.sequence,
    coveredWalHash: b4a.from(walAnchor.hash),
    epochFloor: manifest.epochFloor,
    descriptorSequenceFloor: manifest.descriptorSequenceFloor,
    descriptorHashFloor: b4a.from(manifest.descriptorHashFloor),
    snapshotByteLength: BigInt(snapshotBytes.byteLength),
    snapshotHash: controlSnapshotHash(snapshotBytes),
    ...overrides
  }
}

async function semanticVerifier ({ header, declaredEntryCount, entries }) {
  let entryCount = 0
  for await (const entry of entries) {
    b4a.from(entry.key)
    b4a.from(entry.value)
    entryCount++
  }
  if (entryCount !== declaredEntryCount) throw new Error('semantic fixture count mismatch')
  return { ...header, entryCount }
}

async function writeContentAddressed (controlDirectory, prefix, hash, canonical) {
  const target = path.join(controlDirectory, `${prefix}-${b4a.toString(hash, 'hex')}.v1`)
  await fs.writeFile(target, canonical, { mode: 0o600 })
  return target
}

async function treeSnapshot (root, relative = '') {
  const output = []
  const directory = path.join(root, relative)
  for (const name of (await fs.readdir(directory)).sort()) {
    const childRelative = relative ? path.join(relative, name) : name
    const target = path.join(root, childRelative)
    const stat = await fs.lstat(target)
    const item = {
      path: childRelative,
      mode: stat.mode & 0o777,
      nlink: stat.nlink,
      kind: stat.isDirectory() ? 'directory' : 'file'
    }
    if (stat.isFile()) item.bytes = b4a.toString(await fs.readFile(target), 'hex')
    output.push(item)
    if (stat.isDirectory()) output.push(...await treeSnapshot(root, childRelative))
  }
  return output
}

async function fixture (t, options = {}) {
  const root = await createBlindBoundaryScratch('hiverelay-local-checkpoint-')
  await fs.chmod(root, 0o700)
  t.teardown(() => removeBlindBoundaryScratch(root))

  const descriptor = descriptorValue()
  const descriptorCanonical = encodeCanonical(blindServiceDescriptorV1, descriptor)
  let manifest = decodeCanonical(blindStoreManifestV1, manifestBytes({
    descriptor,
    canonicalBytes: descriptorCanonical
  }), { copyBytes: true })

  const seed = new BlindTransactionStore(transactionOptions(root, manifest))
  await seed.open(async () => {})
  const firstFrame = await seed.append({
    type: 1,
    transactionId: bytes(32, 0xa1),
    virtualBucket: 7,
    payload: b4a.from('first durable frame')
  })
  await seed.close()

  const firstSnapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(manifest, firstFrame.sequence, firstFrame.walHash, 1))
  const firstCheckpoint = checkpointValue(manifest, firstSnapshotBytes, {
    sequence: firstFrame.sequence,
    hash: firstFrame.walHash
  })
  const firstCheckpointBytes = encodeCanonical(blindLocalCheckpointV1, firstCheckpoint)
  const firstCheckpointHash = localCheckpointHash(firstCheckpointBytes)
  manifest = decodeCanonical(blindStoreManifestV1, encodeCanonical(blindStoreManifestV1, {
    ...manifest,
    checkpointWalSequence: firstFrame.sequence,
    checkpointHash: firstCheckpointHash
  }), { copyBytes: true })

  const controlDirectory = path.join(root, 'control')
  await writeContentAddressed(controlDirectory, 'snapshot', controlSnapshotHash(firstSnapshotBytes), firstSnapshotBytes)
  await writeContentAddressed(controlDirectory, 'checkpoint', firstCheckpointHash, firstCheckpointBytes)
  if (options.extraArtifacts) await options.extraArtifacts({ root, controlDirectory, manifest, firstCheckpointHash })

  const manifestStore = new TwoSlotManifestStore({
    controlDirectory,
    manifestKey: MANIFEST_KEY,
    expectedBindings: expectedBindings(manifest)
  })
  await manifestStore.open()
  await manifestStore.initialize(manifest)
  await manifestStore.close()

  const session = new BlindStoreSession({ root })
  await session.open()
  const transactionStore = new BlindTransactionStore(
    transactionOptions(root, manifest, session.lockContext()))
  await transactionStore.open(async () => {})
  const activeManifestStore = new TwoSlotManifestStore({
    controlDirectory,
    manifestKey: MANIFEST_KEY,
    expectedBindings: expectedBindings(manifest)
  })
  await activeManifestStore.open()
  const checkpointStore = createUnsafeTestOnlyBlindLocalCheckpointStore({
    controlDirectory,
    expectedBindings: expectedBindings(manifest),
    maximumSnapshotBytes: 1024 * 1024,
    maximumEntries: 1024,
    maximumSnapshotSourceChunks: options.maximumSnapshotSourceChunks,
    faultInjector: options.faultInjector
  }, semanticVerifier)
  const treeBeforeCheckpointOpen = await treeSnapshot(root)
  await checkpointStore.open({ validationOnly: options.validationOnly === true })

  t.teardown(async () => {
    await checkpointStore.close().catch(() => {})
    await activeManifestStore.close().catch(() => {})
    await transactionStore.close().catch(() => {})
    await session.close().catch(() => {})
  })
  return {
    root,
    controlDirectory,
    manifest,
    activeManifestStore,
    checkpointStore,
    transactionStore,
    session,
    firstFrame,
    firstSnapshotBytes,
    firstCheckpoint,
    firstCheckpointBytes,
    firstCheckpointHash,
    treeBeforeCheckpointOpen
  }
}

async function validateCurrent (state) {
  const manifestSnapshot = await state.activeManifestStore.load()
  return state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.validateManifestCheckpoint({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor
    }))
}

test('validation-only checkpoint recovery is streaming, lock-bound, and byte-for-byte immutable', async t => {
  const state = await fixture(t, {
    validationOnly: true,
    extraArtifacts: async ({ controlDirectory }) => {
      await fs.writeFile(path.join(controlDirectory,
        `.snapshot-${'a'.repeat(64)}.v1.${'b'.repeat(32)}.tmp`), b4a.from('recovery evidence'), { mode: 0o600 })
      await fs.writeFile(path.join(controlDirectory,
        `snapshot-${'c'.repeat(64)}.v1`), b4a.from('unreferenced orphan'), { mode: 0o600 })
    }
  })
  t.alike(await treeSnapshot(state.root), state.treeBeforeCheckpointOpen)
  const validated = await validateCurrent(state)
  t.is(validated.header.checkpointRevision, 1n)
  t.is(validated.snapshot.entryCount, 2)
  t.is(validated.historicalSnapshotsValidated, false)
  t.alike(await treeSnapshot(state.root), state.treeBeforeCheckpointOpen)
  await t.exception.all(() => state.checkpointStore.publish({}), /validation-only mode/)
})

test('checkpoint publication installs snapshot then header and advances the manifest exactly once', async t => {
  const state = await fixture(t)
  await validateCurrent(state)
  const secondFrame = await state.transactionStore.append({
    type: 2,
    transactionId: bytes(32, 0xa2),
    virtualBucket: 8,
    payload: b4a.from('second durable frame')
  })
  const manifestSnapshot = await state.activeManifestStore.load()
  const secondSnapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, secondFrame.sequence, secondFrame.walHash, 2))
  const secondCheckpoint = checkpointValue(state.manifest, secondSnapshotBytes, {
    sequence: secondFrame.sequence,
    hash: secondFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  const published = await state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint: secondCheckpoint,
      snapshotBytes: secondSnapshotBytes
    }))
  t.is(published.header.checkpointRevision, 2n)
  t.is(published.walPruned, false)
  t.is(published.checkpointGcPerformed, false)
  t.alike(await fs.readFile(path.join(state.controlDirectory,
    `snapshot-${b4a.toString(secondCheckpoint.snapshotHash, 'hex')}.v1`)), secondSnapshotBytes)
  t.alike(await fs.readFile(path.join(state.controlDirectory,
    `checkpoint-${b4a.toString(published.headerHash, 'hex')}.v1`)), published.headerBytes)

  const selected = await state.activeManifestStore.load()
  t.alike(selected.manifest.checkpointHash, published.headerHash)
  t.is(selected.manifest.checkpointWalSequence, secondFrame.sequence)
  const revalidated = await state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.validateManifestCheckpoint({
      manifestSnapshot: selected,
      walBarrierAuthority,
      verifiedWalAnchor
    }))
  t.is(revalidated.predecessors.length, 1)
  t.alike(revalidated.predecessors[0].hash, state.firstCheckpointHash)
})

test('fault before manifest CAS leaves the old manifest valid and exact retry is idempotent', async t => {
  let armed = true
  const state = await fixture(t, {
    faultInjector: async point => {
      if (armed && point === 'checkpoint:before-manifest-cas') throw new Error('simulated pre-CAS crash')
    }
  })
  await validateCurrent(state)
  const secondFrame = await state.transactionStore.append({
    type: 3,
    transactionId: bytes(32, 0xa3),
    virtualBucket: 9,
    payload: b4a.from('third durable frame')
  })
  const oldManifest = await state.activeManifestStore.load()
  const secondSnapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, secondFrame.sequence, secondFrame.walHash, 3))
  const secondCheckpoint = checkpointValue(state.manifest, secondSnapshotBytes, {
    sequence: secondFrame.sequence,
    hash: secondFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  const attempt = () => state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot: oldManifest,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint: secondCheckpoint,
      snapshotBytes: secondSnapshotBytes
    }))
  await t.exception(attempt(), /simulated pre-CAS crash/)
  t.alike((await state.activeManifestStore.load()).hash, oldManifest.hash)

  armed = false
  const published = await attempt()
  t.is(published.header.checkpointRevision, 2n)
})

test('forged WAL anchors and publication without startup validation fail before filesystem mutation', async t => {
  const state = await fixture(t)
  const before = await treeSnapshot(state.root)
  const manifestSnapshot = await state.activeManifestStore.load()
  await t.exception(state.checkpointStore.validateManifestCheckpoint({
    manifestSnapshot,
    walBarrierAuthority: Object.freeze({ root: state.root }),
    verifiedWalAnchor: Object.freeze({ root: state.root, sequence: 1n, hash: state.firstFrame.walHash })
  }), /forged|invalid/)
  t.alike(await treeSnapshot(state.root), before)

  const secondSnapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, 2n, bytes(32, 0xee), 4))
  const secondCheckpoint = checkpointValue(state.manifest, secondSnapshotBytes, {
    sequence: 2n,
    hash: bytes(32, 0xee)
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  await t.exception(state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint: secondCheckpoint,
      snapshotBytes: secondSnapshotBytes
    })), /has not been validated/)
  t.alike(await treeSnapshot(state.root), before)
})

test('fault after snapshot temp fsync preserves recovery evidence and never calls manifest CAS', async t => {
  let armed = true
  const state = await fixture(t, {
    faultInjector: async point => {
      if (armed && point === 'checkpoint:snapshot:after-temp-sync') {
        armed = false
        throw new Error('simulated post-temp-fsync crash')
      }
    }
  })
  await validateCurrent(state)
  const nextFrame = await state.transactionStore.append({
    type: 4,
    transactionId: bytes(32, 0xa4),
    virtualBucket: 10,
    payload: b4a.from('fourth durable frame')
  })
  const manifestSnapshot = await state.activeManifestStore.load()
  const snapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, nextFrame.sequence, nextFrame.walHash, 5))
  const checkpoint = checkpointValue(state.manifest, snapshotBytes, {
    sequence: nextFrame.sequence,
    hash: nextFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  await t.exception(state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint,
      snapshotBytes
    })), /post-temp-fsync crash/)
  t.alike((await state.activeManifestStore.load()).hash, manifestSnapshot.hash)
  const snapshotHex = b4a.toString(checkpoint.snapshotHash, 'hex')
  const names = await fs.readdir(state.controlDirectory)
  const temporaryNames = names.filter(name =>
    new RegExp(`^\\.snapshot-${snapshotHex}\\.v1\\.[0-9a-f]{32}\\.tmp$`).test(name))
  t.is(temporaryNames.length, 1)
  t.alike(await fs.readFile(path.join(state.controlDirectory, temporaryNames[0])), snapshotBytes)
  await t.exception(fs.lstat(path.join(state.controlDirectory, `snapshot-${snapshotHex}.v1`)), /ENOENT/)
})

test('a conflicting immutable target is never overwritten and blocks manifest CAS', async t => {
  const state = await fixture(t)
  await validateCurrent(state)
  const nextFrame = await state.transactionStore.append({
    type: 5,
    transactionId: bytes(32, 0xa5),
    virtualBucket: 11,
    payload: b4a.from('fifth durable frame')
  })
  const manifestSnapshot = await state.activeManifestStore.load()
  const snapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, nextFrame.sequence, nextFrame.walHash, 6))
  const checkpoint = checkpointValue(state.manifest, snapshotBytes, {
    sequence: nextFrame.sequence,
    hash: nextFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  const target = path.join(state.controlDirectory,
    `snapshot-${b4a.toString(checkpoint.snapshotHash, 'hex')}.v1`)
  const conflictingBytes = b4a.alloc(snapshotBytes.byteLength, 0x7f)
  await fs.writeFile(target, conflictingBytes, { mode: 0o600 })
  await t.exception(state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint,
      snapshotBytes
    })), /conflicting bytes/)
  t.alike(await fs.readFile(target), conflictingBytes)
  t.alike((await state.activeManifestStore.load()).hash, manifestSnapshot.hash)
})

test('invalid snapshot bytes are rejected before a content-addressed final can be installed', async t => {
  const state = await fixture(t)
  await validateCurrent(state)
  const nextFrame = await state.transactionStore.append({
    type: 7,
    transactionId: bytes(32, 0xa7),
    virtualBucket: 13,
    payload: b4a.from('seventh durable frame')
  })
  const manifestSnapshot = await state.activeManifestStore.load()
  const canonicalSnapshot = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, nextFrame.sequence, nextFrame.walHash, 8))
  const checkpoint = checkpointValue(state.manifest, canonicalSnapshot, {
    sequence: nextFrame.sequence,
    hash: nextFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  const invalidSnapshot = b4a.alloc(canonicalSnapshot.byteLength, 0x5e)
  await t.exception(state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint,
      snapshotBytes: invalidSnapshot
    })), /snapshot version|hash does not match|must be nonzero/)
  const finalPath = path.join(state.controlDirectory,
    `snapshot-${b4a.toString(checkpoint.snapshotHash, 'hex')}.v1`)
  await t.exception(fs.lstat(finalPath), /ENOENT/)
  t.alike((await state.activeManifestStore.load()).hash, manifestSnapshot.hash)
})

test('streamed snapshot sources are length/chunk bounded and closed on failure', async t => {
  const state = await fixture(t, { maximumSnapshotSourceChunks: 2 })
  await validateCurrent(state)
  const nextFrame = await state.transactionStore.append({
    type: 6,
    transactionId: bytes(32, 0xa6),
    virtualBucket: 12,
    payload: b4a.from('sixth durable frame')
  })
  const manifestSnapshot = await state.activeManifestStore.load()
  const snapshotBytes = encodeCanonical(blindControlStateSnapshotV1,
    snapshotValue(state.manifest, nextFrame.sequence, nextFrame.walHash, 7))
  const checkpoint = checkpointValue(state.manifest, snapshotBytes, {
    sequence: nextFrame.sequence,
    hash: nextFrame.walHash
  }, {
    checkpointRevision: 2n,
    previousCheckpointHash: state.firstCheckpointHash
  })
  const attempt = source => state.transactionStore.withWalBarrier((walBarrierAuthority, verifiedWalAnchor) =>
    state.checkpointStore.publish({
      manifestSnapshot,
      walBarrierAuthority,
      verifiedWalAnchor,
      checkpoint,
      snapshotBytes: source
    }))

  async function * shortSource () {
    yield snapshotBytes.subarray(0, snapshotBytes.byteLength - 1)
  }
  await t.exception(attempt(shortSource()), /declared length/)

  let longClosed = false
  async function * longSource () {
    try {
      yield snapshotBytes
      yield b4a.from([0])
    } finally {
      longClosed = true
    }
  }
  await t.exception(attempt(longSource()), /exceeds its declared length/)
  t.is(longClosed, true)

  let chunkBoundClosed = false
  async function * tooManyChunks () {
    try {
      yield b4a.alloc(0)
      yield b4a.alloc(0)
      yield snapshotBytes
    } finally {
      chunkBoundClosed = true
    }
  }
  await t.exception(attempt(tooManyChunks()), /chunk bound/)
  t.is(chunkBoundClosed, true)
  t.alike((await state.activeManifestStore.load()).hash, manifestSnapshot.hash)
})

test('checkpoint store has one in-process owner and close racing open cannot resurrect it', async t => {
  const state = await fixture(t)
  await t.exception.all(() => new BlindLocalCheckpointStore({
    controlDirectory: state.controlDirectory,
    expectedBindings: expectedBindings(state.manifest),
    maximumSnapshotBytes: 1024 * 1024
  }), /semantic authority is required/)
  const competing = createUnsafeTestOnlyBlindLocalCheckpointStore({
    controlDirectory: state.controlDirectory,
    expectedBindings: expectedBindings(state.manifest),
    maximumSnapshotBytes: 1024 * 1024
  }, semanticVerifier)
  await t.exception(competing.open(), /active in-process owner/)
  await competing.close()

  await state.checkpointStore.close()
  let unblock
  const blocked = new Promise(resolve => { unblock = resolve })
  let reached
  const inspected = new Promise(resolve => { reached = resolve })
  const racing = createUnsafeTestOnlyBlindLocalCheckpointStore({
    controlDirectory: state.controlDirectory,
    expectedBindings: expectedBindings(state.manifest),
    maximumSnapshotBytes: 1024 * 1024,
    faultInjector: async point => {
      if (point === 'checkpoint:open:after-directory-inspection') {
        reached()
        await blocked
      }
    }
  }, semanticVerifier)
  const opening = racing.open()
  await inspected
  const closing = racing.close()
  unblock()
  await t.exception(opening, /closed while opening/)
  await closing
  await t.exception(racing.open(), /closed/)
})
