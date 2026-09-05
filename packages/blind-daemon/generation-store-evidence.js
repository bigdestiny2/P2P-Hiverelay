import { createBlindCellInboxCoreControlSnapshotSemanticAuthority, createBlindCellInboxCoreControlSnapshotSemanticVerifier } from './cell-inbox-core-control-snapshot.js'
import { createBlindCellInboxControlSnapshotSemanticAuthority, createBlindCellInboxControlSnapshotSemanticVerifier } from './cell-inbox-control-snapshot.js'
import { createBlindCoreControlSnapshotSemanticAuthority, createBlindCoreControlSnapshotSemanticVerifier } from './core-control-snapshot.js'
import { createBlindInboxControlSnapshotSemanticAuthority, createBlindInboxControlSnapshotSemanticVerifier } from './inbox-control-snapshot.js'
import { createBlindCellControlSnapshotSemanticAuthority, createBlindCellControlSnapshotSemanticVerifier } from './cell-control-snapshot.js'
import path from 'node:path'
import fs from 'node:fs/promises'
import { TwoSlotManifestStore } from './manifest-store.js'
import { BlindLocalCheckpointStore, verifyBlindLocalCheckpointRecoveryValidation } from './local-checkpoint-store.js'
import b4a from 'b4a'
import { BlindCellStorageEngine } from './storage-engine.js'
import { BlindInboxStorageEngine } from './inbox-storage-engine.js'
import { BlindCoreStorageEngine } from './core-storage-engine.js'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'
import { verifyBlindWalRecoveryScanResult } from './wal-recovery-scan.js'

const EVIDENCE = new WeakMap()
const ENGINES = Object.freeze({ cell: BlindCellStorageEngine, inbox: BlindInboxStorageEngine, core: BlindCoreStorageEngine })

function assertDescriptorFloor (snapshot, activated) {
  if (activated == null) return
  const persisted = snapshot.manifest
  let code
  if (activated.sequence < persisted.descriptorSequenceFloor) code = 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_ROLLBACK'
  else if (activated.sequence === persisted.descriptorSequenceFloor && !b4a.equals(activated.hash, persisted.descriptorHashFloor)) code = 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_FORK'
  if (code) {
    const error = new Error(code === 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_ROLLBACK'
      ? 'activated descriptor is below the persisted two-slot manifest floor'
      : 'activated descriptor forks the persisted two-slot manifest floor')
    error.code = code
    throw error
  }
}

// Full semantic replay is deliberately tied to the assembled engines. No
// caller callback can turn a mechanical scan into semantic startup authority.
// Pruned histories need snapshot restoration, which these engines do not yet
// implement; the genesis scanner rejects them before any mutable recovery.
export async function inspectBlindGenerationStore ({ role, engineOptions, lease, session, limits, manifestOptions }) {
  const Engine = ENGINES[role]
  if (!Engine) throw new TypeError('unsupported blind startup role')
  const root = engineOptions.root
  await verifyBlindStoreSessionTransactionLease(lease, root)
  const controlNames = session.rootClassification.controlNames
  const fresh = !controlNames.includes('wal.v2') && !controlNames.some(name => name.startsWith('wal-')) &&
    ['pristine', 'genesis-incomplete'].includes(session.rootClassification.kind)
  const descriptorFloor = manifestOptions?.descriptorFloor == null
    ? null
    : Object.freeze({
      sequence: manifestOptions.descriptorFloor.sequence, hash: b4a.from(manifestOptions.descriptorFloor.hash)
    })
  let checkpointStore
  let manifestStore
  let checkpoint
  let manifestSnapshot
  async function close () {
    try { if (checkpointStore) await checkpointStore.close() } finally { if (manifestStore) await manifestStore.close() }
  }
  try {
    if (manifestOptions) {
      manifestStore = new TwoSlotManifestStore({ ...manifestOptions, controlDirectory: path.join(root, 'control') })
      await manifestStore.open({ validationOnly: true })
      manifestSnapshot = await manifestStore.load()
      assertDescriptorFloor(manifestSnapshot, descriptorFloor)
      const cellVerifier = createBlindCellControlSnapshotSemanticVerifier(createBlindCellControlSnapshotSemanticAuthority())
      const inboxVerifier = createBlindInboxControlSnapshotSemanticVerifier(createBlindInboxControlSnapshotSemanticAuthority())
      const coreVerifier = createBlindCoreControlSnapshotSemanticVerifier(createBlindCoreControlSnapshotSemanticAuthority())
      const cellInboxVerifier = createBlindCellInboxControlSnapshotSemanticVerifier(
        createBlindCellInboxControlSnapshotSemanticAuthority({ cellVerifier, inboxVerifier }))
      const snapshotSemanticVerifier = createBlindCellInboxCoreControlSnapshotSemanticVerifier(
        createBlindCellInboxCoreControlSnapshotSemanticAuthority({ cellInboxVerifier, coreVerifier }))
      checkpointStore = new BlindLocalCheckpointStore({
        controlDirectory: path.join(root, 'control'),
        expectedBindings: manifestSnapshot.manifest,
        snapshotSemanticVerifier,
        maximumEntries: 262144,
        maximumSnapshotBytes: 256 * 1024 * 1024
      })
      await checkpointStore.open({ validationOnly: true })
      checkpoint = await checkpointStore.validateManifestCheckpointForRecovery({ lease, manifestSnapshot })
    }
    const requiredAnchor = checkpoint ? { sequence: checkpoint.checkpointSequence, hash: checkpoint.checkpointWalHash } : null
    const scan = fresh ? null : await Engine.inspectGeneration(engineOptions, { lease, limits, requiredAnchor })
    await session.assertUnchanged()
    const result = Object.freeze({
      role,
      snapshotValidated: checkpoint != null,
      storeEvidence: Object.freeze({
        walSequence: scan ? scan.wal.headSequence : 0n,
        get walHash () { return scan ? scan.wal.headHash : b4a.alloc(32) }
      }),
      hasIrreversibleState: scan ? scan.hasIrreversibleState : false,
      usage: scan ? Object.freeze({ bytes: scan.wal.observedWalBytes, frames: scan.wal.completeFrameCount, segments: scan.wal.sealedSegmentCount }) : Object.freeze({ bytes: 0, frames: 0, segments: 0 })
    })
    EVIDENCE.set(result, { root, lease, scan, checkpoint, manifestSnapshot, manifestStore, descriptorFloor, close })
    return result
  } catch (error) {
    await close().catch(() => {})
    throw error
  }
}

export async function closeBlindGenerationStoreEvidence (result) {
  const state = EVIDENCE.get(result)
  if (state) await state.close()
}

export async function verifyBlindGenerationStoreEvidence (result, root, lease) {
  const state = EVIDENCE.get(result)
  if (!state || state.root !== root || state.lease !== lease) throw new Error('invalid blind generation store evidence')
  await verifyBlindStoreSessionTransactionLease(lease, root)
  if (state.scan) await verifyBlindWalRecoveryScanResult(state.scan.wal, root, lease)
  else {
    try {
      const directory = await fs.opendir(path.join(root, 'control'))
      let count = 0
      for await (const entry of directory) {
        if (++count > 4096) throw new Error('fresh WAL namespace exceeds bound')
        if (entry.name === 'wal.v2' || entry.name.startsWith('wal-')) throw new Error('WAL appeared after fresh root validation')
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }
  if (state.checkpoint) {
    await verifyBlindLocalCheckpointRecoveryValidation(state.checkpoint, root, lease, state.manifestSnapshot)
    const observed = await state.manifestStore.load()
    assertDescriptorFloor(observed, state.descriptorFloor)
    if (!b4a.equals(observed.bytes, state.manifestSnapshot.bytes) || observed.slot !== state.manifestSnapshot.slot) {
      throw new Error('manifest changed during generation startup')
    }
  }
  return true
}
