import fs from 'node:fs/promises'
import os from 'node:os'
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
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import {
  createBlindCellControlSnapshotSemanticAuthority,
  createBlindCellControlSnapshotSemanticVerifier,
  streamBlindCellControlSnapshotEntries
} from '../cell-control-snapshot.js'
import { createUnsafeTestOnlyBlindLocalCheckpointStore } from '../local-checkpoint-store.js'
import { TwoSlotManifestStore } from '../manifest-store.js'
import {
  BLIND_RECOVERY_VALIDATION_AUTHORITY_STATUS,
  BlindRecoveryValidationCoordinator,
  verifyBlindRecoveryValidationAuthority
} from '../recovery-validation-authority.js'
import {
  BlindStoreSession,
  acquireBlindStoreSessionTransactionLease,
  verifyBlindStoreSessionTransactionLease
} from '../store-session.js'
import {
  BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS,
  BlindTransactionStore
} from '../transaction-store.js'
import {
  descriptorValue,
  manifestBytes
} from './coordinator-fixtures.js'

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

function transactionOptions (root, manifest, extra = {}) {
  return {
    root,
    partitionKey: bytes(32, 0x71),
    mapGeneration: manifest.mapGeneration,
    ownerFenceTokenHash: manifest.writerFenceTokenHash,
    durabilityContinuityHash: manifest.durabilityContinuityHash,
    ...extra
  }
}

function emptyCellState (manifest) {
  return {
    relayPublicKey: b4a.from(manifest.relayPublicKey),
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
    epochFloor: manifest.epochFloor,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

async function snapshotBytes (manifest, walFrame, cellAuthority) {
  const entries = []
  for await (const entry of streamBlindCellControlSnapshotEntries(cellAuthority, emptyCellState(manifest))) {
    entries.push(entry)
  }
  return encodeCanonical(blindControlStateSnapshotV1, {
    version: 1,
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    storeId: b4a.from(manifest.storeId),
    durabilityContinuityHash: b4a.from(manifest.durabilityContinuityHash),
    walSequence: walFrame.sequence,
    walHash: b4a.from(walFrame.walHash),
    entries
  })
}

function checkpointValue (manifest, canonicalSnapshot, walFrame) {
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
    coveredWalSequence: walFrame.sequence,
    coveredWalHash: b4a.from(walFrame.walHash),
    epochFloor: manifest.epochFloor,
    descriptorSequenceFloor: manifest.descriptorSequenceFloor,
    descriptorHashFloor: b4a.from(manifest.descriptorHashFloor),
    snapshotByteLength: BigInt(canonicalSnapshot.byteLength),
    snapshotHash: controlSnapshotHash(canonicalSnapshot)
  }
}

async function treeSnapshot (root, relative = '') {
  const output = []
  for (const name of (await fs.readdir(path.join(root, relative))).sort()) {
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

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

async function fixture (t, options = {}) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-joint-recovery-'))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))

  const descriptor = descriptorValue()
  const descriptorCanonical = encodeCanonical(blindServiceDescriptorV1, descriptor)
  let manifest = decodeCanonical(blindStoreManifestV1, manifestBytes({
    descriptor,
    canonicalBytes: descriptorCanonical
  }), { copyBytes: true })
  const seed = new BlindTransactionStore(transactionOptions(root, manifest))
  await seed.open(async () => {})
  const frames = []
  for (let index = 1; index <= 2; index++) {
    frames.push(await seed.append({
      type: 220 + index,
      transactionId: bytes(32, 0xa0 + index),
      virtualBucket: index,
      payload: b4a.from(`joint-recovery-${index}`)
    }))
  }
  await seed.close()

  const cellSemanticAuthority = createBlindCellControlSnapshotSemanticAuthority({ partitionKey: bytes(32, 0x71) })
  const cellSemanticVerifier = createBlindCellControlSnapshotSemanticVerifier(cellSemanticAuthority)
  const canonicalSnapshot = await snapshotBytes(manifest, frames[0], cellSemanticAuthority)
  const checkpoint = checkpointValue(manifest, canonicalSnapshot, frames[0])
  const checkpointBytes = encodeCanonical(blindLocalCheckpointV1, checkpoint)
  const checkpointHash = localCheckpointHash(checkpointBytes)
  manifest = decodeCanonical(blindStoreManifestV1, encodeCanonical(blindStoreManifestV1, {
    ...manifest,
    checkpointWalSequence: frames[0].sequence,
    checkpointHash
  }), { copyBytes: true })

  const controlDirectory = path.join(root, 'control')
  await fs.writeFile(path.join(controlDirectory,
    `snapshot-${b4a.toString(controlSnapshotHash(canonicalSnapshot), 'hex')}.v1`), canonicalSnapshot, { mode: 0o600 })
  await fs.writeFile(path.join(controlDirectory,
    `checkpoint-${b4a.toString(checkpointHash, 'hex')}.v1`), checkpointBytes, { mode: 0o600 })
  const manifestInitializer = new TwoSlotManifestStore({
    controlDirectory,
    manifestKey: MANIFEST_KEY,
    expectedBindings: expectedBindings(manifest)
  })
  await manifestInitializer.open()
  await manifestInitializer.initialize(manifest)
  await manifestInitializer.close()

  const walPath = path.join(controlDirectory, 'wal.v2')
  const completeWalBytes = (await fs.stat(walPath)).size
  if (options.tornTailBytes) await fs.appendFile(walPath, b4a.alloc(options.tornTailBytes, 0xff))

  const session = new BlindStoreSession({ root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  const manifestStore = new TwoSlotManifestStore({
    controlDirectory,
    manifestKey: MANIFEST_KEY,
    expectedBindings: expectedBindings(manifest)
  })
  await manifestStore.open({ validationOnly: true })
  const checkpointStore = createUnsafeTestOnlyBlindLocalCheckpointStore({
    controlDirectory,
    expectedBindings: expectedBindings(manifest),
    maximumSnapshotBytes: 1024 * 1024,
    maximumEntries: 1024
  }, cellSemanticVerifier)
  await checkpointStore.open({ validationOnly: true })
  const coordinator = new BlindRecoveryValidationCoordinator({
    root,
    manifestStore,
    checkpointStore,
    maximumWalBytes: 1024 * 1024,
    maximumWalFrames: 1024,
    maximumWalPayloadBytes: 1024 * 1024
  })
  const transactions = []
  t.teardown(async () => {
    for (const transaction of transactions) await transaction.close().catch(() => {})
    await coordinator.close().catch(() => {})
    await checkpointStore.close().catch(() => {})
    await manifestStore.close().catch(() => {})
    lease.release()
    await session.close().catch(() => {})
  })
  return {
    root,
    controlDirectory,
    walPath,
    completeWalBytes,
    frames,
    manifest,
    session,
    lease,
    manifestStore,
    checkpointStore,
    coordinator,
    transactions
  }
}

test('joint recovery authority composes exact manifest, Cell snapshot, and WAL scan identities without mutation', async t => {
  const state = await fixture(t)
  const before = await treeSnapshot(state.root)
  const replayed = []
  const authority = await state.coordinator.validate({
    lease: state.lease,
    applyShadowFrame: async frame => { replayed.push(frame.sequence) }
  })
  t.alike(replayed, [2n])
  t.alike(await treeSnapshot(state.root), before)
  t.is(await verifyBlindRecoveryValidationAuthority(authority, state.root, state.lease), true)
  t.is(authority.checkpointSequence, 1n)
  t.is(authority.walHeadSequence, 2n)
  t.is(authority.productionReady, false)
  t.is(authority.publicationAuthorized, false)
  t.is(BLIND_RECOVERY_VALIDATION_AUTHORITY_STATUS.blocker,
    'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED')

  authority.manifestHash.fill(0)
  authority.checkpointWalHash.fill(0)
  authority.walHeadHash.fill(0)
  t.is(await verifyBlindRecoveryValidationAuthority(authority, state.root, state.lease), true)
  await rejectsCode(t,
    verifyBlindRecoveryValidationAuthority(Object.freeze({ ...authority }), state.root, state.lease),
    'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')
  await rejectsCode(t,
    verifyBlindRecoveryValidationAuthority(authority, `${state.root}-wrong`, state.lease),
    'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')
  await rejectsCode(t,
    verifyBlindRecoveryValidationAuthority(authority, state.root, Object.freeze({ root: state.root })),
    'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')
})

test('transaction consumes the exact joint authority, repairs afterward, and releases the lock last', async t => {
  const state = await fixture(t, { tornTailBytes: 29 })
  const before = await treeSnapshot(state.root)
  const authority = await state.coordinator.validate({
    lease: state.lease,
    applyShadowFrame: async () => {}
  })
  t.is(authority.tornTailBytes, 29)
  t.alike(await treeSnapshot(state.root), before)
  const recovered = []
  const transaction = new BlindTransactionStore(transactionOptions(state.root, state.manifest, {
    recoveryHandoff: {
      lease: state.lease,
      validationResult: authority,
      validate: async context => {
        t.is(context.mutationAllowed, false)
        t.is(context.authorityStatus.blocker, 'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED')
        t.is(await verifyBlindRecoveryValidationAuthority(
          context.validationResult,
          state.root,
          context.lease
        ), true)
        return context.validationResult
      }
    }
  }))
  state.transactions.push(transaction)
  await transaction.open(async frame => { recovered.push(frame.sequence) })
  t.alike(recovered, [1n, 2n])
  t.is((await fs.stat(state.walPath)).size, state.completeWalBytes)
  t.is(BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS.productionReady, false)
  await rejectsCode(t,
    verifyBlindStoreSessionTransactionLease(state.lease, state.root),
    'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  state.lease.release()

  const competing = await fs.open(path.join(state.controlDirectory, 'writer.lock.v1'), 'r+')
  t.is(tryExclusiveFileLock(competing), false)
  let sessionClosed = false
  const closing = state.session.close().then(() => { sessionClosed = true })
  await Promise.resolve()
  t.is(sessionClosed, false)
  t.is(tryExclusiveFileLock(competing), false)
  await transaction.close()
  await closing
  t.is(sessionClosed, true)
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
})

test('post-validation WAL mutation expires authority before callback or lease transfer', async t => {
  const state = await fixture(t)
  const authority = await state.coordinator.validate({ lease: state.lease, applyShadowFrame: async () => {} })
  await fs.appendFile(state.walPath, b4a.from([0xff]))
  await t.exception(verifyBlindRecoveryValidationAuthority(authority, state.root, state.lease), /WAL changed/)
  let callbackCalled = false
  const transaction = new BlindTransactionStore(transactionOptions(state.root, state.manifest, {
    recoveryHandoff: {
      lease: state.lease,
      validationResult: authority,
      validate: async result => {
        callbackCalled = true
        return result.validationResult
      }
    }
  }))
  state.transactions.push(transaction)
  await t.exception(transaction.open(async () => {}), /WAL changed/)
  t.is(callbackCalled, false)
  t.is(await verifyBlindStoreSessionTransactionLease(state.lease, state.root), true)
  t.is((await fs.stat(state.walPath)).size, state.completeWalBytes + 1)
})

test('post-validation manifest or snapshot substitution invalidates the joint proof', async t => {
  for (const kind of ['manifest', 'snapshot']) {
    const state = await fixture(t)
    const authority = await state.coordinator.validate({ lease: state.lease, applyShadowFrame: async () => {} })
    const name = kind === 'manifest'
      ? 'manifest-a.v1'
      : (await fs.readdir(state.controlDirectory)).find(name => name.startsWith('snapshot-'))
    const target = path.join(state.controlDirectory, name)
    const replaced = await fs.readFile(target)
    replaced[Math.floor(replaced.byteLength / 2)] ^= 1
    await fs.writeFile(target, replaced, { mode: 0o600 })
    await t.exception(
      verifyBlindRecoveryValidationAuthority(authority, state.root, state.lease),
      /manifest|snapshot|checkpoint/i
    )
    t.is(await verifyBlindStoreSessionTransactionLease(state.lease, state.root), true, kind)
  }
})

test('authority expires with coordinator or validation-store lifetime and non-validation stores are refused', async t => {
  const state = await fixture(t)
  const authority = await state.coordinator.validate({ lease: state.lease, applyShadowFrame: async () => {} })
  await state.coordinator.close()
  await rejectsCode(t,
    verifyBlindRecoveryValidationAuthority(authority, state.root, state.lease),
    'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')

  const storeExpiry = await fixture(t)
  const storeAuthority = await storeExpiry.coordinator.validate({
    lease: storeExpiry.lease,
    applyShadowFrame: async () => {}
  })
  await storeExpiry.checkpointStore.close()
  await t.exception(
    verifyBlindRecoveryValidationAuthority(storeAuthority, storeExpiry.root, storeExpiry.lease),
    /stale|invalid/
  )

  const fakeManifest = {
    controlDirectory: state.controlDirectory,
    opened: true,
    validationOnly: false,
    closing: false,
    load: async () => {}
  }
  const fakeCheckpoint = {
    controlDirectory: state.controlDirectory,
    opened: true,
    validationOnly: true,
    closing: false,
    validateManifestCheckpointForRecovery: async () => {}
  }
  try {
    const invalid = new BlindRecoveryValidationCoordinator({
      root: state.root,
      manifestStore: fakeManifest,
      checkpointStore: fakeCheckpoint
    })
    t.absent(invalid)
    t.fail('expected validation-only constructor refusal')
  } catch (error) {
    t.is(error.code, 'BLIND_RECOVERY_VALIDATION_ONLY_REQUIRED')
  }
})

test('a valid joint authority callback failure retains caller lease and byte-exact state', async t => {
  const state = await fixture(t, { tornTailBytes: 13 })
  const authority = await state.coordinator.validate({ lease: state.lease, applyShadowFrame: async () => {} })
  const before = await treeSnapshot(state.root)
  const transaction = new BlindTransactionStore(transactionOptions(state.root, state.manifest, {
    recoveryHandoff: {
      lease: state.lease,
      validationResult: authority,
      validate: async context => {
        t.is(await verifyBlindRecoveryValidationAuthority(
          context.validationResult,
          state.root,
          context.lease
        ), true)
        throw new Error('final shadow-state check refused handoff')
      }
    }
  }))
  state.transactions.push(transaction)
  await t.exception(transaction.open(async () => {}), /final shadow-state check refused handoff/)
  t.is(await verifyBlindStoreSessionTransactionLease(state.lease, state.root), true)
  t.alike(await treeSnapshot(state.root), before)
})
