import path from 'node:path'
import b4a from 'b4a'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'
import { verifyBlindManifestSnapshot } from './manifest-store.js'
import {
  verifyBlindLocalCheckpointRecoveryValidation,
  verifyBlindLocalCheckpointSnapshotSemanticAuthority
} from './local-checkpoint-store.js'
import {
  scanBlindWalV2ForAnchoredRecovery,
  verifyBlindWalRecoveryScanResult
} from './wal-recovery-scan.js'

const ACTIVE_AUTHORITIES = new WeakSet()
const AUTHORITY_STATE = new WeakMap()
const COORDINATOR_STATE = new WeakMap()

export const BLIND_RECOVERY_VALIDATION_AUTHORITY_STATUS = Object.freeze({
  jointMechanicalAuthorityImplemented: true,
  cellSnapshotSemanticAuthorityRequired: true,
  allFamilyShadowSemanticAuthorityImplemented: false,
  productionReady: false,
  publicationAuthorized: false,
  blocker: 'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED'
})

export class BlindRecoveryValidationAuthorityError extends Error {
  constructor (message, code = 'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID') {
    super(message)
    this.name = 'BlindRecoveryValidationAuthorityError'
    this.code = code
  }
}

function canonicalRoot (root) {
  if (typeof root !== 'string' || root.includes('\0') || !path.isAbsolute(root) || path.normalize(root) !== root) {
    throw new TypeError('recovery validation root must be a canonical absolute path')
  }
  return root
}

function requireObject (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${field} must be an object`)
  return value
}

function coordinatorState (coordinator) {
  const state = COORDINATOR_STATE.get(coordinator)
  if (!state) throw new BlindRecoveryValidationAuthorityError('recovery validation coordinator identity is invalid')
  return state
}

function sameVisibleAuthority (authority, state) {
  return authority.root === state.root &&
    b4a.equals(authority.manifestHash, state.manifestHash) &&
    b4a.equals(authority.checkpointHeaderHash, state.checkpointHeaderHash) &&
    authority.checkpointSequence === state.checkpointSequence &&
    b4a.equals(authority.checkpointWalHash, state.checkpointWalHash) &&
    authority.walHeadSequence === state.walHeadSequence &&
    b4a.equals(authority.walHeadHash, state.walHeadHash) &&
    authority.tornTailOffset === state.tornTailOffset &&
    authority.tornTailBytes === state.tornTailBytes &&
    authority.productionReady === false && authority.publicationAuthorized === false
}

function sameManifestSnapshotBytes (left, right) {
  return left && right && left.slot === right.slot && left.needsRepair === right.needsRepair &&
    b4a.equals(left.hash, right.hash) && b4a.equals(left.bytes, right.bytes)
}

function mintAuthority (coordinator, lease, manifestSnapshot, checkpointValidation, walRecoveryResult) {
  const privateCoordinator = coordinatorState(coordinator)
  const state = Object.freeze({
    coordinator,
    generation: privateCoordinator.generation,
    root: privateCoordinator.root,
    lease,
    manifestSnapshot,
    checkpointValidation,
    snapshotSemanticAuthority: checkpointValidation.snapshotSemanticAuthority,
    walRecoveryResult,
    manifestHash: b4a.from(checkpointValidation.manifestHash),
    checkpointHeaderHash: b4a.from(checkpointValidation.checkpointHeaderHash),
    checkpointSequence: checkpointValidation.checkpointSequence,
    checkpointWalHash: b4a.from(checkpointValidation.checkpointWalHash),
    walHeadSequence: walRecoveryResult.headSequence,
    walHeadHash: b4a.from(walRecoveryResult.headHash),
    tornTailOffset: walRecoveryResult.tornTailOffset,
    tornTailBytes: walRecoveryResult.tornTailBytes
  })
  const authority = {}
  Object.defineProperties(authority, {
    root: { enumerable: true, value: state.root },
    manifestHash: { enumerable: true, get: () => b4a.from(state.manifestHash) },
    checkpointHeaderHash: { enumerable: true, get: () => b4a.from(state.checkpointHeaderHash) },
    checkpointSequence: { enumerable: true, value: state.checkpointSequence },
    checkpointWalHash: { enumerable: true, get: () => b4a.from(state.checkpointWalHash) },
    walHeadSequence: { enumerable: true, value: state.walHeadSequence },
    walHeadHash: { enumerable: true, get: () => b4a.from(state.walHeadHash) },
    tornTailOffset: { enumerable: true, value: state.tornTailOffset },
    tornTailBytes: { enumerable: true, value: state.tornTailBytes },
    productionReady: { enumerable: true, value: false },
    publicationAuthorized: { enumerable: true, value: false }
  })
  Object.freeze(authority)
  ACTIVE_AUTHORITIES.add(authority)
  AUTHORITY_STATE.set(authority, state)
  if (privateCoordinator.currentAuthority) ACTIVE_AUTHORITIES.delete(privateCoordinator.currentAuthority)
  privateCoordinator.currentAuthority = authority
  return authority
}

export async function verifyBlindRecoveryValidationAuthority (authority, expectedRoot, lease) {
  const root = canonicalRoot(expectedRoot)
  if (!authority || typeof authority !== 'object' || !ACTIVE_AUTHORITIES.has(authority)) {
    throw new BlindRecoveryValidationAuthorityError('recovery validation authority is forged, expired, or unsupported')
  }
  const state = AUTHORITY_STATE.get(authority)
  const privateCoordinator = state && COORDINATOR_STATE.get(state.coordinator)
  if (!state || !privateCoordinator || state.root !== root || state.lease !== lease ||
      !privateCoordinator.opened || privateCoordinator.closing || privateCoordinator.closed ||
      !privateCoordinator.manifestStore.opened || !privateCoordinator.manifestStore.validationOnly ||
      privateCoordinator.manifestStore.closing || !privateCoordinator.checkpointStore.opened ||
      !privateCoordinator.checkpointStore.validationOnly || privateCoordinator.checkpointStore.closing ||
      privateCoordinator.generation !== state.generation || privateCoordinator.currentAuthority !== authority ||
      !sameVisibleAuthority(authority, state)) {
    throw new BlindRecoveryValidationAuthorityError('recovery validation authority binding is stale or invalid')
  }
  await verifyBlindStoreSessionTransactionLease(lease, root)
  verifyBlindManifestSnapshot(state.manifestSnapshot, privateCoordinator.controlDirectory)
  await verifyBlindLocalCheckpointRecoveryValidation(
    state.checkpointValidation,
    root,
    lease,
    state.manifestSnapshot
  )
  await verifyBlindLocalCheckpointSnapshotSemanticAuthority(
    state.snapshotSemanticAuthority,
    state.checkpointValidation,
    root,
    lease
  )
  await verifyBlindWalRecoveryScanResult(state.walRecoveryResult, root, lease)
  const refreshedManifest = await privateCoordinator.manifestStore.load()
  if (!sameManifestSnapshotBytes(refreshedManifest, state.manifestSnapshot)) {
    throw new BlindRecoveryValidationAuthorityError('manifest changed after joint recovery validation')
  }
  if (state.checkpointValidation.checkpointSequence !== state.walRecoveryResult.checkpointSequence ||
      !b4a.equals(state.checkpointValidation.checkpointWalHash, state.walRecoveryResult.checkpointHash)) {
    throw new BlindRecoveryValidationAuthorityError('checkpoint and WAL recovery authorities do not share one anchor')
  }
  return true
}

export class BlindRecoveryValidationCoordinator {
  constructor (options = {}) {
    const root = canonicalRoot(options.root)
    const manifestStore = requireObject(options.manifestStore, 'manifestStore')
    const checkpointStore = requireObject(options.checkpointStore, 'checkpointStore')
    if (typeof manifestStore.load !== 'function') throw new TypeError('manifestStore.load must be a function')
    if (typeof checkpointStore.validateManifestCheckpointForRecovery !== 'function') {
      throw new TypeError('checkpointStore must support validation-only recovery proof')
    }
    if (manifestStore.controlDirectory !== path.join(root, 'control') ||
        checkpointStore.controlDirectory !== path.join(root, 'control')) {
      throw new TypeError('recovery validation stores must bind the exact root/control directory')
    }
    if (!manifestStore.opened || manifestStore.validationOnly !== true || manifestStore.closing ||
        !checkpointStore.opened || checkpointStore.validationOnly !== true || checkpointStore.closing) {
      throw new BlindRecoveryValidationAuthorityError(
        'recovery validation requires already-open validation-only manifest and checkpoint stores',
        'BLIND_RECOVERY_VALIDATION_ONLY_REQUIRED'
      )
    }
    COORDINATOR_STATE.set(this, {
      root,
      controlDirectory: path.join(root, 'control'),
      manifestStore,
      checkpointStore,
      maximumWalBytes: options.maximumWalBytes,
      maximumWalFrames: options.maximumWalFrames,
      maximumWalPayloadBytes: options.maximumWalPayloadBytes,
      opened: true,
      closing: false,
      closed: false,
      generation: 1,
      currentAuthority: null,
      serial: Promise.resolve()
    })
  }

  validate (options = {}) {
    const state = coordinatorState(this)
    if (!state.opened || state.closing || state.closed) {
      return Promise.reject(new Error('recovery validation coordinator is closed'))
    }
    if (typeof options.applyShadowFrame !== 'function') {
      return Promise.reject(new TypeError('applyShadowFrame must be an awaited shadow-state callback'))
    }
    const operation = state.serial.then(async () => {
      if (!state.opened || state.closing || state.closed) throw new Error('recovery validation coordinator is closed')
      if (!state.manifestStore.opened || state.manifestStore.validationOnly !== true || state.manifestStore.closing ||
          !state.checkpointStore.opened || state.checkpointStore.validationOnly !== true || state.checkpointStore.closing) {
        throw new BlindRecoveryValidationAuthorityError(
          'recovery validation store lifetime or validation-only mode changed',
          'BLIND_RECOVERY_VALIDATION_ONLY_REQUIRED'
        )
      }
      const lease = options.lease
      await verifyBlindStoreSessionTransactionLease(lease, state.root)
      const manifestSnapshot = await state.manifestStore.load()
      verifyBlindManifestSnapshot(manifestSnapshot, state.controlDirectory)
      const checkpointValidation = await state.checkpointStore.validateManifestCheckpointForRecovery({
        lease,
        manifestSnapshot
      })
      await verifyBlindLocalCheckpointRecoveryValidation(
        checkpointValidation,
        state.root,
        lease,
        manifestSnapshot
      )
      await verifyBlindLocalCheckpointSnapshotSemanticAuthority(
        checkpointValidation.snapshotSemanticAuthority,
        checkpointValidation,
        state.root,
        lease
      )
      const walRecoveryResult = await scanBlindWalV2ForAnchoredRecovery({
        root: state.root,
        lease,
        checkpoint: {
          sequence: checkpointValidation.checkpointSequence,
          hash: checkpointValidation.checkpointWalHash
        },
        mapGeneration: checkpointValidation.mapGeneration,
        writerFenceTokenHash: checkpointValidation.writerFenceTokenHash,
        durabilityContinuityHash: checkpointValidation.durabilityContinuityHash,
        maximumWalBytes: state.maximumWalBytes,
        maximumWalFrames: state.maximumWalFrames,
        maximumWalPayloadBytes: state.maximumWalPayloadBytes,
        applyShadowFrame: options.applyShadowFrame
      })
      await verifyBlindWalRecoveryScanResult(walRecoveryResult, state.root, lease)
      await verifyBlindLocalCheckpointRecoveryValidation(
        checkpointValidation,
        state.root,
        lease,
        manifestSnapshot
      )
      await verifyBlindStoreSessionTransactionLease(lease, state.root)
      const refreshedManifest = await state.manifestStore.load()
      if (!sameManifestSnapshotBytes(refreshedManifest, manifestSnapshot)) {
        throw new BlindRecoveryValidationAuthorityError('manifest changed during joint recovery validation')
      }
      return mintAuthority(this, lease, manifestSnapshot, checkpointValidation, walRecoveryResult)
    })
    state.serial = operation.catch(() => {})
    return operation
  }

  close () {
    const state = coordinatorState(this)
    if (state.closed) return Promise.resolve()
    state.closing = true
    const closing = state.serial.then(() => {
      state.opened = false
      state.closing = false
      state.closed = true
      state.generation++
      if (state.currentAuthority) ACTIVE_AUTHORITIES.delete(state.currentAuthority)
      state.currentAuthority = null
    })
    state.serial = closing.catch(() => {})
    return closing
  }
}
