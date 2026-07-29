import b4a from 'b4a'
import fs from 'node:fs/promises'
import path from 'node:path'
import test from 'brittle'
import { blake2b256 } from '@hiverelay/blind-protocol'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'
import {
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3,
  openForwardHttpsAggregateQuotaV3,
  mintForwardHttpsAggregateQuotaCapabilitiesV3,
  closeForwardHttpsAggregateQuotaV3,
  beginForwardHttpsAggregateQuotaRecoveryV3,
  absorbForwardHttpsAggregateQuotaRecoveryFrameV3,
  finishForwardHttpsAggregateQuotaRecoveryV3
} from '../forward-https-replay-journal-v4.js'
import {
  FORWARD_HTTPS_STORAGE_V3_LIMITS,
  FORWARD_HTTPS_STORAGE_V3_STATUS,
  FORWARD_HTTPS_STORAGE_V3_ERROR_CODE,
  FORWARD_HTTPS_STORAGE_V3_FAULT_POINT,
  openForwardHttpsStorageAuthorityV3,
  sourceForwardHttpsStorageAuthorityV3,
  targetForwardHttpsStorageAuthorityV3,
  consumeForwardHttpsStorageReplayV3,
  forwardHttpsStorageAuthorityV3Status,
  verifyForwardHttpsStorageAuthorityV3,
  closeForwardHttpsStorageAuthorityV3
} from '../forward-https-storage-authority-v3.js'
import {
  prepareForwardHttpsSourceTurnV3,
  forwardHttpsSourceStoreV3Status
} from '../forward-https-source-store-v3.js'

const SOURCE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const ZERO32 = b4a.alloc(32)

function fixed (byte) {
  return b4a.alloc(32, byte)
}

async function quota (t, role) {
  const base = await createBlindBoundaryScratch('fhq-')
  t.teardown(async () => { await removeBlindBoundaryScratch(base) })
  const roots = {}
  for (const name of ['source-replay', 'target-replay', 'source-store', 'target-store']) {
    roots[name] = path.join(base, name)
    await fs.mkdir(roots[name], { mode: 0o700 })
    await fs.chmod(roots[name], 0o700)
  }
  const authority = await openForwardHttpsAggregateQuotaV3({
    sourceReplayRoot: roots['source-replay'],
    targetReplayRoot: roots['target-replay'],
    sourceStoreRoot: roots['source-store'],
    targetStoreRoot: roots['target-store'],
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184,
    monotonicMillis: () => Date.now(),
    callbackTimeoutMillis: 15000,
    faultInjector: null
  })
  t.teardown(async () => { await closeForwardHttpsAggregateQuotaV3(authority).catch(() => {}) })
  const capabilities = mintForwardHttpsAggregateQuotaCapabilitiesV3(authority)
  return { authority, capabilities, capability: role === SOURCE ? capabilities.sourceStoreQuotaCapability : capabilities.targetStoreQuotaCapability, roots }
}

async function absorbOne (capability, walType, payload) {
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  try {
    return await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
      frame: { type: walType, payload, payloadHash: blake2b256(payload), sequence: 1n, previousWalHash: ZERO32, walHash: blake2b256(b4a.concat([b4a.from('wal'), payload])), frameBytes: payload.byteLength + 224 }
    })
  } finally {
    await finishForwardHttpsAggregateQuotaRecoveryV3(sink).catch(() => {})
  }
}

function writeU64be (output, offset, value) {
  let current = BigInt(value)
  for (let index = 7; index >= 0; index--) { output[offset + index] = Number(current & 0xffn); current >>= 8n }
  return offset + 8
}

// Test-side FTM9 payload builder (frozen 192-byte layout; caller-supplied
// exact payloads, the requested-terminal-arm shape).
function buildFtm9 (input) {
  const output = b4a.alloc(192)
  let offset = 0
  b4a.copy(b4a.from('FTM9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = input.role === 'TARGET' ? 2 : 1
  output.writeUInt16BE(input.flags, offset); offset += 2
  b4a.copy(input.stableSessionId, output, offset); offset += 32
  offset = writeU64be(output, offset, input.sequence)
  for (const value of input.buckets || [0, 0, 0, 0, 0]) { output.writeUInt16BE(value, offset); offset += 2 }
  output.writeUInt16BE(input.transportTurnsSpent || 0, offset); offset += 2
  output.writeUInt32BE(input.transportBytesSpent || 0, offset); offset += 4
  offset = writeU64be(output, offset, input.priorSessionRevision || 0n)
  output.writeUInt32BE(input.newTrustedEpochHighWatermark || 0, offset); offset += 4
  const reason = b4a.from(input.reason, 'ascii')
  output[offset++] = reason.byteLength
  b4a.copy(reason, output, offset); offset += 64
  if (input.flags === 1) {
    output.writeUInt32BE(input.expiresAtEpoch, offset); offset += 4
    output.writeUInt32BE(input.retainedUntilEpoch, offset); offset += 4
    b4a.copy(input.exactRequestCommitment, output, offset); offset += 32
  }
  return output
}

// The exact minimal-terminal authority commitment preimage (v13): M is
// always recomputed, so tests recompute it the same way.
function minimalTerminalM (roleByte, id, sequence, requestCommitment, expiresAtEpoch, retainedUntilEpoch, watermark, reason) {
  const sequenceBytes = b4a.alloc(8)
  let current = BigInt(sequence)
  for (let index = 7; index >= 0; index--) { sequenceBytes[index] = Number(current & 0xffn); current >>= 8n }
  const scalars = b4a.alloc(13)
  scalars.writeUInt32BE(expiresAtEpoch, 0)
  scalars.writeUInt32BE(retainedUntilEpoch, 4)
  scalars.writeUInt32BE(watermark, 8)
  scalars[12] = reason.byteLength
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-minimal-terminal-authority.v3', 'ascii'),
    b4a.from([roleByte]), id, sequenceBytes, requestCommitment, scalars, reason
  ]))
}

test('FTM9 flags0 golden: exact192 payload, zero tail, nonzero prior revision', async t => {
  const id = fixed(0x51)
  const payload = buildFtm9({
    role: 'SOURCE',
    flags: 0,
    stableSessionId: id,
    sequence: 7n,
    priorSessionRevision: 4n,
    newTrustedEpochHighWatermark: 1234,
    reason: 'CHAIN_INVALID',
    buckets: [1, 2, 3, 1, 90],
    transportTurnsSpent: 97,
    transportBytesSpent: 97 * 131072
  })
  t.is(payload.byteLength, 192)
  t.is(b4a.toString(payload.subarray(0, 4), 'ascii'), 'FTM9')
  t.is(payload[4], 1)
  t.is(payload[5], 1)
  t.is(payload.readUInt16BE(6), 0)
  t.ok(b4a.equals(payload.subarray(8, 40), id))
  t.is(payload.readUInt16BE(48), 1)
  t.is(payload.readUInt16BE(58), 97)
  t.is(payload.readUInt32BE(60), 97 * 131072)
  t.is(payload.readUInt32BE(72), 1234)
  t.is(payload[76], 13)
  t.is(b4a.toString(payload.subarray(77, 90), 'ascii'), 'CHAIN_INVALID')
  for (let index = 90; index < 192; index++) t.is(payload[index], 0)
  t.is(192 + 224, 416)
  t.is(192 + 416, 608)
})

test('FTM9 flags1 golden: minimal absent-sequence terminal, exact clock and commitment', async t => {
  const id = fixed(0x52)
  const expiresAtEpoch = 300000
  const payload = buildFtm9({
    role: 'TARGET',
    flags: 1,
    stableSessionId: id,
    sequence: 11n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 999,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x53),
    expiresAtEpoch,
    retainedUntilEpoch: expiresAtEpoch + 900
  })
  t.is(payload.byteLength, 192)
  t.is(payload[5], 2)
  t.is(payload.readUInt16BE(6), 1)
  t.is(payload.readUInt32BE(141), expiresAtEpoch)
  t.is(payload.readUInt32BE(145), expiresAtEpoch + 900)
  // The frozen minimal tail carries the exact request commitment at 149..181;
  // M is recomputed from the payload fields, never stored in the tail.
  t.ok(b4a.equals(payload.subarray(149, 181), fixed(0x53)))
  for (let index = 181; index < 192; index++) t.is(payload[index], 0)
  // M recomputation is exact and deterministic
  const M = minimalTerminalM(2, id, 11n, fixed(0x53), expiresAtEpoch, expiresAtEpoch + 900, 999, b4a.from('FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID', 'ascii'))
  const c7 = blake2b256(b4a.concat([b4a.from('hiverelay.blind.forward-https-retention-lookup.v3', 'ascii'), M]))
  const c9 = blake2b256(b4a.concat([b4a.from('hiverelay.blind.forward-https-terminal-state.v3', 'ascii'), M]))
  t.absent(b4a.equals(c7, ZERO32))
  t.absent(b4a.equals(c9, ZERO32))
  t.absent(b4a.equals(c7, c9))
})

test('FTM9 decode horizon: expiry above 4294966394 is INTEGRITY; boundary admits', async t => {
  const id = fixed(0x54)
  const base = {
    role: 'SOURCE',
    flags: 1,
    stableSessionId: id,
    sequence: 1n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x55),
    retainedUntilEpoch: 4294966394 + 900
  }
  const { capability } = await quota(t, SOURCE)
  await t.exception.all(absorbOne(capability, 99, buildFtm9({ ...base, expiresAtEpoch: 4294966395 })), /horizon|INTEGRITY/)
  const ok = buildFtm9({ ...base, expiresAtEpoch: 4294966394 })
  t.is(ok.readUInt32BE(145), 4294966394 + 900)
  const { entry } = await absorbOne(capability, 99, ok)
  t.is(entry.terminalLogicalCharge, 608)
  t.is(entry.authorityBitmap, 640)
})

test('FTM9 flags1 decode rejects nonzero counters, wrong reason, nonzero revision', async t => {
  const id = fixed(0x56)
  const base = {
    role: 'SOURCE',
    flags: 1,
    stableSessionId: id,
    sequence: 1n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x57),
    expiresAtEpoch: 100,
    retainedUntilEpoch: 1000
  }
  const { capability } = await quota(t, SOURCE)
  await t.exception.all(absorbOne(capability, 99, buildFtm9({ ...base, buckets: [1, 0, 0, 0, 0] })), /FTM9/)
  await t.exception.all(absorbOne(capability, 99, buildFtm9({ ...base, reason: 'CHAIN_INVALID' })), /FTM9/)
  await t.exception.all(absorbOne(capability, 99, buildFtm9({ ...base, priorSessionRevision: 1n })), /FTM9/)
})

test('storage constants: exact production liabilities, headroom and ceilings', async t => {
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.slotLiabilityUnconsumedLogicalBytes, 1344)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.slotLiabilityUnconsumedPhysicalBytes, 896)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.slotLiabilityConsumedUnprunedLogicalBytes, 736)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.slotLiabilityConsumedUnprunedPhysicalBytes, 480)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionHeadroomLogicalPerRole, 88080384)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionHeadroomPhysicalPerRole, 58720256)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionHeadroomLogicalAggregate, 176160768)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionHeadroomPhysicalAggregate, 117440512)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionOrdinaryLogicalCeilingPerStoreAtFreshRoot, 8501854208)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.productionOrdinaryPhysicalCeilingPerStoreAtFreshRoot, 8531214336)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.terminalLogicalBytes, 608)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.pruneLogicalBytes, 736)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.readinessOperationBits, 0)
  t.is(FORWARD_HTTPS_STORAGE_V3_LIMITS.runtimeReady, false)
  t.is(FORWARD_HTTPS_STORAGE_V3_STATUS.runtimeReady, false)
})

test('export surfaces: exact set equality on all four modules, removed names absent', async t => {
  const source = await import('../forward-https-source-store-v3.js')
  const target = await import('../forward-https-target-store-v3.js')
  const storage = await import('../forward-https-storage-authority-v3.js')
  const replay = await import('../forward-https-replay-journal-v4.js')
  t.alike(Object.keys(source).sort(), [
    'FORWARD_HTTPS_SOURCE_STORE_V3_ERROR_CODE',
    'FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT',
    'FORWARD_HTTPS_SOURCE_STORE_V3_LIMITS',
    'FORWARD_HTTPS_SOURCE_STORE_V3_STATUS',
    'FORWARD_HTTPS_SOURCE_WAL_TYPE',
    'ForwardHttpsSourceStoreV3Error',
    'closeForwardHttpsSourceStoreV3',
    'forwardHttpsSourceStoreV3Status',
    'forwardHttpsSourceTurnStateV3',
    'openForwardHttpsSourceStoreV3',
    'persistForwardHttpsSourceResultV3',
    'prepareForwardHttpsSourceTurnV3'
  ].sort())
  t.alike(Object.keys(target).sort(), [
    'FORWARD_HTTPS_TARGET_STORE_V3_ERROR_CODE',
    'FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT',
    'FORWARD_HTTPS_TARGET_STORE_V3_LIMITS',
    'FORWARD_HTTPS_TARGET_STORE_V3_STATUS',
    'FORWARD_HTTPS_TARGET_WAL_TYPE',
    'ForwardHttpsTargetStoreV3Error',
    'acceptForwardedHttpsTargetTurnV3',
    'closeForwardHttpsTargetStoreV3',
    'forwardHttpsTargetStoreV3Status',
    'forwardHttpsTargetTurnStateV3',
    'openForwardHttpsTargetStoreV3',
    'runNextForwardHttpsTargetProcessorWorkV3'
  ].sort())
  t.alike(Object.keys(storage).sort(), [
    'FORWARD_HTTPS_STORAGE_V3_ERROR_CODE',
    'FORWARD_HTTPS_STORAGE_V3_FAULT_POINT',
    'FORWARD_HTTPS_STORAGE_V3_LIMITS',
    'FORWARD_HTTPS_STORAGE_V3_STATUS',
    'ForwardHttpsStorageAuthorityV3Error',
    'closeForwardHttpsStorageAuthorityV3',
    'consumeForwardHttpsStorageReplayV3',
    'forwardHttpsStorageAuthorityV3Status',
    'openForwardHttpsStorageAuthorityV3',
    'sourceForwardHttpsStorageAuthorityV3',
    'targetForwardHttpsStorageAuthorityV3',
    'verifyForwardHttpsStorageAuthorityV3'
  ].sort())
  t.is(Object.keys(replay).length, 39, 'replay module carries the frozen 39 exports')
  t.absent(Object.keys(replay).includes('beginForwardHttpsAggregateQuotaWalAttemptV3'), 'begin is module-private')
  t.ok(Object.keys(replay).includes('applyForwardHttpsAggregateQuotaWalFrameV3'), 'composite apply present')
  t.absent(Object.keys(replay).includes('FORWARD_HTTPS_STORE_WAL_QUOTA_REGISTRY_V3'), 'registry never exported')
  // Removed names are gone from the surfaces
  for (const removed of ['prepareForwardHttpsSourceSessionV3', 'appendForwardHttpsSourceSessionV3', 'terminalizeForwardHttpsSourceSessionV3', 'terminalizeForwardHttpsSourceAbsentSequenceV3', 'pruneForwardHttpsSourceSessionV3', 'FORWARD_HTTPS_SOURCE_STORE_V3_WAL_TYPE']) {
    t.absent(removed in source, `source no longer exports ${removed}`)
  }
  for (const removed of ['openForwardHttpsTargetSessionV3', 'appendForwardHttpsTargetSessionV3', 'terminalizeForwardHttpsTargetSessionV3', 'terminalizeForwardHttpsTargetAbsentSequenceV3', 'pruneForwardHttpsTargetSessionV3', 'FORWARD_HTTPS_TARGET_STORE_V3_WAL_TYPE', 'FORWARD_HTTPS_TARGET_STORE_V3_HISTORIC_IDENTITY']) {
    t.absent(removed in target, `target no longer exports ${removed}`)
  }
  for (const removed of ['encodeForwardHttpsSessionTerminalV3', 'createForwardHttpsChargeRegistryV3', 'streamForwardHttpsChargeCommitmentV3', 'verifyForwardHttpsTerminalHeadroomV3', 'verifyForwardHttpsTerminalInvarianceV3', 'checkForwardHttpsProtectedAdmissionV3', 'classifyForwardHttpsHistoricIdentityV3', 'deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3', 'deriveForwardHttpsMinimalTerminalAuthorityClassesV3', 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE', 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS', 'FORWARD_HTTPS_STORAGE_SLOT_STATE_V3', 'FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3']) {
    t.absent(removed in storage, `storage no longer exports ${removed}`)
  }
})

test('composite storage authority: exact open order, exposed children, status, verify, consume replay negative, close', async t => {
  const root = await createBlindBoundaryScratch('fhcomp-')
  t.teardown(async () => { await removeBlindBoundaryScratch(root) })
  const options = {
    root,
    manifestKey: fixed(0x30),
    atRestKey: fixed(0x31),
    wireV3AbiHash: fixed(0x32),
    privateIpcV4Hash: fixed(0x33),
    signedLaunchTopologyHash: fixed(0x34),
    sourceStoreId: fixed(0x35),
    targetStoreId: fixed(0x36),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x37),
    sourceDurabilityContinuityHash: fixed(0x38),
    targetDurabilityContinuityHash: fixed(0x39),
    targetSignerPublicKey: fixed(0x3a),
    targetSignerDescriptorSequence: 1n,
    targetSignerDescriptorHash: fixed(0x3b),
    signResult: async () => b4a.alloc(64),
    createResponderState: () => ({}),
    advanceResponderIngress: () => {},
    advanceResponderOutcome: () => {},
    epochSeconds: () => 1000000,
    monotonicMillis: () => Date.now()
  }
  const authority = await openForwardHttpsStorageAuthorityV3(options)
  t.teardown(async () => { await closeForwardHttpsStorageAuthorityV3(authority).catch(() => {}) })
  // Children are exposed only after successful initialization
  const source = sourceForwardHttpsStorageAuthorityV3(authority)
  const target = targetForwardHttpsStorageAuthorityV3(authority)
  t.ok(source && target)
  const status = forwardHttpsStorageAuthorityV3Status(authority)
  t.is(status.state, 'OPEN')
  t.ok(status.localOperational)
  t.is(status.descriptorOperationBits, 0)
  // The exposed child store is fully operational through its own API
  const prepared = await prepareForwardHttpsSourceTurnV3(source, { stableSessionId: fixed(0x3c), body: b4a.alloc(8, 0x41) })
  t.is(prepared.walSequence, 1n)
  t.is(forwardHttpsSourceStoreV3Status(source).unconsumedSlots, forwardHttpsSourceStoreV3Status(source).slotCapacity - 1)
  // Exact authority verification passes and carries both heads
  const verified = verifyForwardHttpsStorageAuthorityV3(authority)
  t.ok(verified.consistent)
  t.is(verified.source.walHeadSequence, 1n)
  // consume replay: a forged consumed capability rejects, no mutation
  await t.exception.all(() => consumeForwardHttpsStorageReplayV3(authority, {
    consumed: Object.freeze({}),
    role: 'SOURCE_ORIGIN',
    record: b4a.alloc(292)
  }), /forged|CONSUMED_INVALID|INVALID/)
  // Missing/unknown open keys reject
  const missing = { ...options }
  delete missing.manifestKey
  await t.exception.all(openForwardHttpsStorageAuthorityV3(missing), /manifestKey/)
  await t.exception.all(openForwardHttpsStorageAuthorityV3({ ...options, bogusKey: 1 }), /unknown field/)
  // Close is exact reverse order and idempotent; foreign authority rejects
  await closeForwardHttpsStorageAuthorityV3(authority)
  t.is(forwardHttpsStorageAuthorityV3Status(authority).state, 'CLOSED')
  await closeForwardHttpsStorageAuthorityV3(authority)
  await t.exception.all(closeForwardHttpsStorageAuthorityV3(Object.freeze({})), /forged|AUTHORITY_INVALID/)
  await t.exception.all(() => sourceForwardHttpsStorageAuthorityV3(authority), /closed|CLOSED/)
})

function compositeOptions (root, faultInjector) {
  return {
    root,
    manifestKey: fixed(0x30),
    atRestKey: fixed(0x31),
    wireV3AbiHash: fixed(0x32),
    privateIpcV4Hash: fixed(0x33),
    signedLaunchTopologyHash: fixed(0x34),
    sourceStoreId: fixed(0x35),
    targetStoreId: fixed(0x36),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x37),
    sourceDurabilityContinuityHash: fixed(0x38),
    targetDurabilityContinuityHash: fixed(0x39),
    targetSignerPublicKey: fixed(0x3a),
    targetSignerDescriptorSequence: 1n,
    targetSignerDescriptorHash: fixed(0x3b),
    signResult: async () => b4a.alloc(64),
    createResponderState: () => ({}),
    advanceResponderIngress: () => {},
    advanceResponderOutcome: () => {},
    epochSeconds: () => 1000000,
    monotonicMillis: () => Date.now(),
    faultInjector
  }
}

test('composite fault registry: lifecycle points fire and injector failures are coded INTEGRITY', async t => {
  // The composite lifecycle subset fires over one open/close, alongside the
  // quota, replay and store points the same injector observes downstream.
  const r1 = await createBlindBoundaryScratch('fhcomp-fault-')
  t.teardown(async () => { await removeBlindBoundaryScratch(r1) })
  const observed = []
  const contexts = []
  const authority = await openForwardHttpsStorageAuthorityV3(compositeOptions(r1, async (point, context) => { observed.push(point); contexts.push(context) }))
  for (const point of ['OPEN_AFTER_ROOT_VERIFY', 'OPEN_AFTER_QUOTA_AUTHORITY', 'OPEN_AFTER_SOURCE_STORE', 'OPEN_AFTER_TARGET_STORE', 'OPEN_AFTER_QUOTA_INITIALIZE']) {
    t.ok(observed.includes(point), `${point} fired`)
  }
  await closeForwardHttpsStorageAuthorityV3(authority)
  t.ok(observed.includes(FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.CLOSE_AFTER_QUOTA), 'close fault point fired')
  t.ok(contexts.every(context => context === undefined), 'no context is passed at any layer')
  // An open-side injector failure rejects the open with coded INTEGRITY.
  const r2 = await createBlindBoundaryScratch('fhcomp-fault-')
  t.teardown(async () => { await removeBlindBoundaryScratch(r2) })
  await t.exception.all(openForwardHttpsStorageAuthorityV3(compositeOptions(r2, async point => {
    if (point === FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_QUOTA_INITIALIZE) throw new Error('injected composite fault')
  })), /fault injector failed at OPEN_AFTER_QUOTA_INITIALIZE|INTEGRITY/)
  // A non-undefined injector return maps to coded INTEGRITY as well.
  const r2b = await createBlindBoundaryScratch('fhcomp-fault-')
  t.teardown(async () => { await removeBlindBoundaryScratch(r2b) })
  await t.exception.all(openForwardHttpsStorageAuthorityV3(compositeOptions(r2b, async point => {
    if (point === FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.OPEN_AFTER_QUOTA_INITIALIZE) return 'injected'
    return undefined
  })), /returned a value|INTEGRITY/)
  // A close-side injector failure is reported once with coded INTEGRITY; the
  // exact-owner repeat resolves because every child already closed.
  const r3 = await createBlindBoundaryScratch('fhcomp-fault-')
  t.teardown(async () => { await removeBlindBoundaryScratch(r3) })
  const authority3 = await openForwardHttpsStorageAuthorityV3(compositeOptions(r3, async point => {
    if (point === FORWARD_HTTPS_STORAGE_V3_FAULT_POINT.CLOSE_AFTER_QUOTA) throw new Error('injected close fault')
  }))
  let closeError = null
  try {
    await closeForwardHttpsStorageAuthorityV3(authority3)
  } catch (error) {
    closeError = error
  }
  t.ok(closeError, 'the first close reports the fault')
  t.is(closeError.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INTEGRITY')
  await closeForwardHttpsStorageAuthorityV3(authority3)
  t.is(forwardHttpsStorageAuthorityV3Status(authority3).state, 'CLOSED')
})

test('readiness flags and error codes: storage STATUS is not implementation-ready and AUTHORITY_INVALID is defined', async t => {
  t.is(FORWARD_HTTPS_STORAGE_V3_STATUS.implementationReady, false)
  t.is(FORWARD_HTTPS_STORAGE_V3_STATUS.runtimeReady, false)
  t.is(FORWARD_HTTPS_STORAGE_V3_STATUS.releaseReady, false)
  t.is(FORWARD_HTTPS_STORAGE_V3_STATUS.authorizesRelease, false)
  t.is(FORWARD_HTTPS_STORAGE_V3_ERROR_CODE.AUTHORITY_INVALID, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_AUTHORITY_INVALID')
  // A forged authority close rejects with the exact coded AUTHORITY_INVALID.
  let forged = null
  try {
    await closeForwardHttpsStorageAuthorityV3(Object.freeze({}))
  } catch (error) {
    forged = error
  }
  t.ok(forged)
  t.is(forged.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_AUTHORITY_INVALID')
})
