// FORWARD HTTPS durability storage authority v3.
//
// Owns the FTM9 terminal-delta codec, the per-role terminal slot lifecycle
// (FREE|PROVISIONAL|ALLOCATED|CONSUMED_UNPRUNED|CONSUMED_PRUNED), the bounded
// removable charge-entry registry with its streaming BLAKE2b-256 commitment,
// the protected aggregate terminal headroom arithmetic and the historic
// identity classification used by recovery. All durable charge/codec facts
// flow through the one hash-bound replay module; this module adds no decoder,
// offset, charge, count, bitmap or registry copy beyond the FTM9 encoder the
// contract assigns to the store-side authority.

import b4a from 'b4a'
import fs from 'node:fs/promises'
import path from 'node:path'
import {
  FORWARD_HTTPS_REPLAY_ROLE_V4,
  openForwardHttpsAggregateQuotaV3,
  mintForwardHttpsAggregateQuotaCapabilitiesV3,
  closeForwardHttpsAggregateQuotaV3,
  forwardHttpsAggregateQuotaV3Status,
  assertForwardHttpsAggregateQuotaOperationalV3,
  beginForwardHttpsAggregateQuotaRecoveryV3,
  finishForwardHttpsAggregateQuotaRecoveryV3,
  initializeForwardHttpsAggregateQuotaV3,
  openForwardHttpsReplayJournalV4,
  closeForwardHttpsReplayJournalV4,
  verifyForwardHttpsReplayConsumedV4
} from './forward-https-replay-journal-v4.js'

const STORAGE_AUTHORITIES = new WeakMap()

const ZERO32 = b4a.alloc(32)
const FTM9_PAYLOAD_BYTES = 192
const FTM9_FRAME_BYTES = 416
const FTM9_LOGICAL_BYTES = 608
const FPR9_LOGICAL_BYTES = 736
const FPR9_FRAME_BYTES = 480
const SLOT_LIABILITY_UNCONSUMED_LOGICAL = 1344
const SLOT_LIABILITY_UNCONSUMED_PHYSICAL = 896
const SLOT_LIABILITY_CONSUMED_UNPRUNED_LOGICAL = 736
const SLOT_LIABILITY_CONSUMED_UNPRUNED_PHYSICAL = 480
const PRODUCTION_SLOTS_PER_ROLE = 65536
const CHARGE_ENTRY_CAP = 65536
const CHARGE_ENTRY_BYTES = 49

const FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE = deepFreeze({
  INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INVALID',
  CAPACITY: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CAPACITY',
  TERMINAL: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_TERMINAL',
  CONFLICT: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CONFLICT',
  SESSION_CLOSED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SESSION_CLOSED',
  BUDGET_EXHAUSTED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_BUDGET_EXHAUSTED',
  SEQUENCE_INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SEQUENCE_INVALID',
  CHAIN_INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CHAIN_INVALID',
  CLOSED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CLOSED',
  INTEGRITY: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INTEGRITY',
  AUTHORITY_INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_AUTHORITY_INVALID'
})

const FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS = deepFreeze({
  productionSlotsPerRole: PRODUCTION_SLOTS_PER_ROLE,
  removableChargeEntryCapPerSession: CHARGE_ENTRY_CAP,
  chargeEntryBytes: CHARGE_ENTRY_BYTES,
  terminalPayloadBytes: FTM9_PAYLOAD_BYTES,
  terminalFrameBytes: FTM9_FRAME_BYTES,
  terminalLogicalBytes: FTM9_LOGICAL_BYTES,
  pruneLogicalBytes: FPR9_LOGICAL_BYTES,
  pruneFrameBytes: FPR9_FRAME_BYTES,
  slotLiabilityUnconsumedLogicalBytes: SLOT_LIABILITY_UNCONSUMED_LOGICAL,
  slotLiabilityUnconsumedPhysicalBytes: SLOT_LIABILITY_UNCONSUMED_PHYSICAL,
  slotLiabilityConsumedUnprunedLogicalBytes: SLOT_LIABILITY_CONSUMED_UNPRUNED_LOGICAL,
  slotLiabilityConsumedUnprunedPhysicalBytes: SLOT_LIABILITY_CONSUMED_UNPRUNED_PHYSICAL,
  productionHeadroomLogicalPerRole: 88080384,
  productionHeadroomPhysicalPerRole: 58720256,
  productionHeadroomLogicalAggregate: 176160768,
  productionHeadroomPhysicalAggregate: 117440512,
  productionOrdinaryLogicalCeilingPerStoreAtFreshRoot: 8501854208,
  productionOrdinaryPhysicalCeilingPerStoreAtFreshRoot: 8531214336,
  productionOrdinaryLogicalCeilingAggregateAtFreshRoot: 17003708416,
  productionOrdinaryPhysicalCeilingAggregateAtFreshRoot: 17062428672,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export class ForwardHttpsStorageAuthorityV3Error extends Error {
  constructor (message, code = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsStorageAuthorityV3Error'
    this.code = code
  }
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function fail (message, code) {
  throw new ForwardHttpsStorageAuthorityV3Error(message, code)
}

// Composite lifecycle fault points (FORWARD_HTTPS_STORAGE_V3_FAULT_POINT):
// the injector observes exactly the point string (no context); any injector
// failure or non-undefined return is a coded INTEGRITY error, never an
// uncoded callback escape.
async function compositeFault (faultInjector, point) {
  if (faultInjector === null) return
  let result
  try {
    result = await faultInjector(point)
  } catch (error) {
    fail(`fault injector failed at ${point}`, FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  if (result !== undefined) fail(`fault injector returned a value at ${point}`, FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
}

function asBytes32 (value, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value) ? value : b4a.from(value)
  if (output.byteLength !== 32) throw new TypeError(`${field} must be exactly 32 bytes`)
  if (nonzero && b4a.equals(output, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return output
}

// V18 storage_module_exact constant names.
export const FORWARD_HTTPS_STORAGE_V3_LIMITS = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS
export const FORWARD_HTTPS_STORAGE_V3_ERROR_CODE = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE
export const FORWARD_HTTPS_STORAGE_V3_STATUS = deepFreeze({
  schemaVersion: 3,
  implementationReady: false,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})
export const FORWARD_HTTPS_STORAGE_V3_FAULT_POINT = deepFreeze({
  OPEN_AFTER_ROOT_VERIFY: 'OPEN_AFTER_ROOT_VERIFY',
  OPEN_AFTER_QUOTA_AUTHORITY: 'OPEN_AFTER_QUOTA_AUTHORITY',
  OPEN_AFTER_SOURCE_REPLAY: 'OPEN_AFTER_SOURCE_REPLAY',
  OPEN_AFTER_TARGET_REPLAY: 'OPEN_AFTER_TARGET_REPLAY',
  OPEN_AFTER_SOURCE_STORE: 'OPEN_AFTER_SOURCE_STORE',
  OPEN_AFTER_TARGET_STORE: 'OPEN_AFTER_TARGET_STORE',
  OPEN_AFTER_QUOTA_INITIALIZE: 'OPEN_AFTER_QUOTA_INITIALIZE',
  CLOSE_AFTER_TARGET_STORE: 'CLOSE_AFTER_TARGET_STORE',
  CLOSE_AFTER_SOURCE_STORE: 'CLOSE_AFTER_SOURCE_STORE',
  CLOSE_AFTER_TARGET_REPLAY: 'CLOSE_AFTER_TARGET_REPLAY',
  CLOSE_AFTER_SOURCE_REPLAY: 'CLOSE_AFTER_SOURCE_REPLAY',
  CLOSE_AFTER_QUOTA: 'CLOSE_AFTER_QUOTA'
})
// ---------------------------------------------------------------------------
// Composite storage authority (retained v4 open_abi.storage composite). The
// composite validates and owns the clocks/callbacks, opens the quota
// authority with exact callback deadline authority, and privately passes only
// role-correct opaque capabilities/sinks to children.
// ---------------------------------------------------------------------------

const COMPOSITE_CHILD_DIRS = ['source-replay', 'target-replay', 'source-store', 'target-store']

function compositeState (authority) {
  const state = authority && STORAGE_AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) fail('storage authority is forged', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.AUTHORITY_INVALID)
  return state
}

function requireClosedObjectKeys (options, required, optional) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be a closed object')
  for (const key of required) if (!Object.hasOwn(options, key)) throw new TypeError(`options.${key} is required`)
  for (const key of Object.keys(options)) if (!required.includes(key) && !optional.includes(key)) throw new TypeError(`options contains unknown field ${key}`)
}

export async function openForwardHttpsStorageAuthorityV3 (options) {
  const required = ['root', 'manifestKey', 'atRestKey', 'wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'sourceStoreId', 'targetStoreId', 'mapGeneration', 'ownerFenceTokenHash', 'sourceDurabilityContinuityHash', 'targetDurabilityContinuityHash', 'targetSignerPublicKey', 'targetSignerDescriptorSequence', 'targetSignerDescriptorHash', 'signResult', 'createResponderState', 'advanceResponderIngress', 'advanceResponderOutcome', 'epochSeconds', 'monotonicMillis']
  requireClosedObjectKeys(options, required, ['limits', 'faultInjector'])
  if (typeof options.root !== 'string' || !path.isAbsolute(options.root)) throw new TypeError('root must be a canonical absolute path')
  const manifestKey = b4a.from(asBytes32(options.manifestKey, 'manifestKey', true))
  const atRestKey = b4a.from(asBytes32(options.atRestKey, 'atRestKey', true))
  const hashes = {}
  for (const field of ['wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'sourceStoreId', 'targetStoreId', 'ownerFenceTokenHash', 'sourceDurabilityContinuityHash', 'targetDurabilityContinuityHash', 'targetSignerPublicKey', 'targetSignerDescriptorHash']) {
    hashes[field] = asBytes32(options[field], field, true)
  }
  if (typeof options.mapGeneration !== 'bigint' || options.mapGeneration <= 0n) throw new TypeError('mapGeneration must be a nonzero u64')
  if (typeof options.targetSignerDescriptorSequence !== 'bigint' || options.targetSignerDescriptorSequence <= 0n) throw new TypeError('targetSignerDescriptorSequence must be a nonzero u64')
  for (const callback of ['signResult', 'createResponderState', 'advanceResponderIngress', 'advanceResponderOutcome']) {
    if (typeof options[callback] !== 'function') throw new TypeError(`${callback} must be a function`)
  }
  if (typeof options.epochSeconds !== 'function') throw new TypeError('epochSeconds must be a function')
  if (typeof options.monotonicMillis !== 'function') throw new TypeError('monotonicMillis must be a function')
  // 1: the composite root and exactly four distinct mode-0700 role children,
  // canonical by path, realpath and dev+ino.
  await fs.mkdir(options.root, { recursive: true, mode: 0o700 })
  await fs.chmod(options.root, 0o700)
  const roots = {}
  for (const name of COMPOSITE_CHILD_DIRS) {
    roots[name] = path.join(options.root, name)
    await fs.mkdir(roots[name], { recursive: true, mode: 0o700 })
    await fs.chmod(roots[name], 0o700)
    if (await fs.realpath(roots[name]) !== roots[name]) fail(`storage child ${name} traverses a symlink`, FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
  }
  const faultInjector = options.faultInjector === undefined ? null : options.faultInjector
  const { openForwardHttpsSourceStoreV3, forwardHttpsSourceStoreV3Status, closeForwardHttpsSourceStoreV3 } = await import('./forward-https-source-store-v3.js')
  const { openForwardHttpsTargetStoreV3, forwardHttpsTargetStoreV3Status, closeForwardHttpsTargetStoreV3 } = await import('./forward-https-target-store-v3.js')
  const opened = { quota: null, capabilities: null, sourceReplay: null, targetReplay: null, sourceStore: null, targetStore: null }
  try {
    await compositeFault(faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_ROOT_VERIFY)
    // 2: aggregate quota physical authority over all four roots.
    opened.quota = await openForwardHttpsAggregateQuotaV3({
      sourceReplayRoot: roots['source-replay'],
      targetReplayRoot: roots['target-replay'],
      sourceStoreRoot: roots['source-store'],
      targetStoreRoot: roots['target-store'],
      maximumDurableBytesPerStore: options.limits && typeof options.limits.maximumDurableBytesPerStore === 'number' ? options.limits.maximumDurableBytesPerStore : 8589934592,
      maximumForwardStorageBytesAggregate: options.limits && typeof options.limits.maximumForwardStorageBytesAggregate === 'number' ? options.limits.maximumForwardStorageBytesAggregate : 17179869184,
      monotonicMillis: options.monotonicMillis,
      callbackTimeoutMillis: options.limits && typeof options.limits.callbackTimeoutMillis === 'number' ? options.limits.callbackTimeoutMillis : 15000,
      faultInjector
    })
    await compositeFault(faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_QUOTA_AUTHORITY)
    // 3: exactly four opaque role capabilities and the two recovery sinks.
    opened.capabilities = mintForwardHttpsAggregateQuotaCapabilitiesV3(opened.quota)
    const sourceSink = beginForwardHttpsAggregateQuotaRecoveryV3(opened.capabilities.sourceStoreQuotaCapability)
    const targetSink = beginForwardHttpsAggregateQuotaRecoveryV3(opened.capabilities.targetStoreQuotaCapability)
    // 4: both replay journals, physical-only bootstrap permitted.
    const replayBase = {
      manifestKey: b4a.from(manifestKey),
      wireV3AbiHash: hashes.wireV3AbiHash,
      privateIpcV4Hash: hashes.privateIpcV4Hash,
      signedLaunchTopologyHash: hashes.signedLaunchTopologyHash,
      mapGeneration: options.mapGeneration,
      ownerFenceTokenHash: hashes.ownerFenceTokenHash,
      monotonicMillis: options.monotonicMillis
    }
    opened.sourceReplay = await openForwardHttpsReplayJournalV4({
      ...replayBase,
      role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
      root: roots['source-replay'],
      replayQuotaCapability: opened.capabilities.sourceReplayQuotaCapability,
      storeId: hashes.sourceStoreId,
      durabilityContinuityHash: hashes.sourceDurabilityContinuityHash,
      faultInjector
    })
    opened.targetReplay = await openForwardHttpsReplayJournalV4({
      ...replayBase,
      role: FORWARD_HTTPS_REPLAY_ROLE_V4.TARGET_INGRESS,
      root: roots['target-replay'],
      replayQuotaCapability: opened.capabilities.targetReplayQuotaCapability,
      storeId: hashes.targetStoreId,
      durabilityContinuityHash: hashes.targetDurabilityContinuityHash,
      faultInjector
    })
    // 5: both stores with their recovery sinks; only recovery plans are
    // permitted before initialization.
    const storeBase = {
      wireV3AbiHash: hashes.wireV3AbiHash,
      privateIpcV4Hash: hashes.privateIpcV4Hash,
      signedLaunchTopologyHash: hashes.signedLaunchTopologyHash,
      mapGeneration: options.mapGeneration,
      ownerFenceTokenHash: hashes.ownerFenceTokenHash,
      epochSeconds: options.epochSeconds,
      monotonicMillis: options.monotonicMillis,
      faultInjector,
      limits: options.limits
    }
    opened.sourceStore = await openForwardHttpsSourceStoreV3({
      ...storeBase,
      root: roots['source-store'],
      replayJournalAuthority: opened.sourceReplay,
      sourceStoreQuotaCapability: opened.capabilities.sourceStoreQuotaCapability,
      sourceQuotaRecoverySink: sourceSink,
      storeId: hashes.sourceStoreId,
      durabilityContinuityHash: hashes.sourceDurabilityContinuityHash
    })
    await compositeFault(faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_SOURCE_STORE)
    opened.targetStore = await openForwardHttpsTargetStoreV3({
      ...storeBase,
      root: roots['target-store'],
      replayJournalAuthority: opened.targetReplay,
      targetStoreQuotaCapability: opened.capabilities.targetStoreQuotaCapability,
      targetQuotaRecoverySink: targetSink,
      storeId: hashes.targetStoreId,
      durabilityContinuityHash: hashes.targetDurabilityContinuityHash,
      targetSignerPublicKey: hashes.targetSignerPublicKey,
      targetSignerDescriptorSequence: options.targetSignerDescriptorSequence,
      targetSignerDescriptorHash: hashes.targetSignerDescriptorHash,
      signResult: options.signResult,
      createResponderState: options.createResponderState,
      advanceResponderIngress: options.advanceResponderIngress,
      advanceResponderOutcome: options.advanceResponderOutcome,
      atRestKey: b4a.from(atRestKey)
    })
    await compositeFault(faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_TARGET_STORE)
    // 6: both sinks finished with the exact same-composite capability binding
    // and quota initialized with the two one-use final recovery states.
    const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sourceSink, opened.capabilities.sourceStoreQuotaCapability)
    const targetFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(targetSink, opened.capabilities.targetStoreQuotaCapability)
    await initializeForwardHttpsAggregateQuotaV3(opened.quota, {
      sourceRecoveryFinalState: sourceFinal,
      targetRecoveryFinalState: targetFinal
    })
    // 7: child authorities and localOperational only after successful
    // initialization.
    assertForwardHttpsAggregateQuotaOperationalV3(opened.capabilities.sourceStoreQuotaCapability)
    await compositeFault(faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_QUOTA_INITIALIZE)
    const authority = Object.freeze({})
    const state = {
      authority,
      root: options.root,
      roots,
      quota: opened.quota,
      capabilities: opened.capabilities,
      sourceReplay: opened.sourceReplay,
      targetReplay: opened.targetReplay,
      sourceStore: opened.sourceStore,
      targetStore: opened.targetStore,
      storeApis: {
        sourceStatus: forwardHttpsSourceStoreV3Status,
        targetStatus: forwardHttpsTargetStoreV3Status,
        closeSource: closeForwardHttpsSourceStoreV3,
        closeTarget: closeForwardHttpsTargetStoreV3
      },
      faultInjector,
      closePromise: null,
      closed: false
    }
    STORAGE_AUTHORITIES.set(authority, state)
    return authority
  } catch (error) {
    // Exact reverse-order cleanup: no partially opened child is exposed.
    if (opened.targetStore) await closeForwardHttpsTargetStoreV3(opened.targetStore).catch(() => {})
    if (opened.sourceStore) await closeForwardHttpsSourceStoreV3(opened.sourceStore).catch(() => {})
    if (opened.targetReplay) await closeForwardHttpsReplayJournalV4(opened.targetReplay).catch(() => {})
    if (opened.sourceReplay) await closeForwardHttpsReplayJournalV4(opened.sourceReplay).catch(() => {})
    if (opened.quota) await closeForwardHttpsAggregateQuotaV3(opened.quota).catch(() => {})
    throw error
  } finally {
    manifestKey.fill(0)
    atRestKey.fill(0)
  }
}

export function sourceForwardHttpsStorageAuthorityV3 (authority) {
  const state = compositeState(authority)
  if (state.closed) fail('storage authority is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  return state.sourceStore
}

export function targetForwardHttpsStorageAuthorityV3 (authority) {
  const state = compositeState(authority)
  if (state.closed) fail('storage authority is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  return state.targetStore
}

// Burn one process-local consumed replay capability against the role-matched
// composite replay journal. One-use; never refunded or reminted.
export function consumeForwardHttpsStorageReplayV3 (authority, input) {
  const state = compositeState(authority)
  if (state.closed) fail('storage authority is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  requireClosedObjectKeys(input, ['consumed', 'role', 'record'], [])
  const role = input.role
  if (role !== FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN && role !== FORWARD_HTTPS_REPLAY_ROLE_V4.TARGET_INGRESS) throw new TypeError('role must be SOURCE_ORIGIN or TARGET_INGRESS')
  const journalAuthority = role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN ? state.sourceReplay : state.targetReplay
  verifyForwardHttpsReplayConsumedV4(input.consumed, { journalAuthority, role, record: input.record })
}

export function forwardHttpsStorageAuthorityV3Status (authority) {
  const state = compositeState(authority)
  const quota = forwardHttpsAggregateQuotaV3Status(state.quota)
  return deepFreeze({
    state: state.closed ? 'CLOSED' : 'OPEN',
    localOperational: !state.closed && quota.localOperational,
    blocker: quota.blocker,
    source: state.storeApis.sourceStatus(state.sourceStore),
    target: state.storeApis.targetStatus(state.targetStore),
    descriptorOperationBits: 0,
    advertisedOperationBits: 0,
    readinessOperationBits: 0,
    runtimeReady: false,
    releaseReady: false,
    authorizesRelease: false
  })
}

// Exact authority verification: both child stores are operational, their WAL
// heads match their own status surfaces and the quota authority is OPEN.
export function verifyForwardHttpsStorageAuthorityV3 (authority) {
  const state = compositeState(authority)
  if (state.closed) fail('storage authority is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  assertForwardHttpsAggregateQuotaOperationalV3(state.capabilities.sourceStoreQuotaCapability)
  assertForwardHttpsAggregateQuotaOperationalV3(state.capabilities.targetStoreQuotaCapability)
  const source = state.storeApis.sourceStatus(state.sourceStore)
  const target = state.storeApis.targetStatus(state.targetStore)
  if (!source.localOperational || !target.localOperational ||
      source.walHeadSequence !== state.sourceStore.walHeadSequence ||
      target.walHeadSequence !== state.targetStore.walHeadSequence ||
      !b4a.equals(source.walHeadHash, state.sourceStore.walHeadHash) ||
      !b4a.equals(target.walHeadHash, state.targetStore.walHeadHash)) {
    fail('storage authority verification failed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  return deepFreeze({
    consistent: true,
    source: Object.freeze({ walHeadSequence: source.walHeadSequence, walHeadHash: b4a.from(source.walHeadHash) }),
    target: Object.freeze({ walHeadSequence: target.walHeadSequence, walHeadHash: b4a.from(target.walHeadHash) })
  })
}

// Exact reverse-order close: target store, source store, target replay,
// source replay, quota. Idempotent for the exact owner.
export function closeForwardHttpsStorageAuthorityV3 (authority) {
  const state = authority && STORAGE_AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) {
    return Promise.reject(new ForwardHttpsStorageAuthorityV3Error('storage authority is forged', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.AUTHORITY_INVALID))
  }
  if (state.closePromise) return state.closePromise
  state.closePromise = (async () => {
    if (state.closed) return
    state.closed = true
    await state.storeApis.closeTarget(state.targetStore).catch(() => {})
    await state.storeApis.closeSource(state.sourceStore).catch(() => {})
    await closeForwardHttpsReplayJournalV4(state.targetReplay).catch(() => {})
    await closeForwardHttpsReplayJournalV4(state.sourceReplay).catch(() => {})
    await closeForwardHttpsAggregateQuotaV3(state.quota).catch(() => {})
    // Failure-atomic toward CLOSED: a close-fault failure is reported once on
    // this first close; the exact-owner repeat resolves because every child
    // already closed absorbing.
    let closeFault = null
    try {
      await compositeFault(state.faultInjector, FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.CLOSE_AFTER_QUOTA)
    } catch (error) {
      closeFault = error
    }
    if (closeFault !== null) {
      state.closePromise = Promise.resolve()
      throw closeFault
    }
  })()
  return state.closePromise
}
