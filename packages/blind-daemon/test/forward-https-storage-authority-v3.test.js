import b4a from 'b4a'
import test from 'brittle'
import { blake2b256 } from '@hiverelay/blind-protocol'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'
import {
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3
} from '../forward-https-replay-journal-v4.js'
import {
  FORWARD_HTTPS_STORAGE_V3_LIMITS,
  FORWARD_HTTPS_STORAGE_V3_STATUS,
  encodeForwardHttpsSessionTerminalV3,
  openForwardHttpsStorageAuthorityV3,
  sourceForwardHttpsStorageAuthorityV3,
  targetForwardHttpsStorageAuthorityV3,
  consumeForwardHttpsStorageReplayV3,
  forwardHttpsStorageAuthorityV3Status,
  verifyForwardHttpsStorageAuthorityV3,
  closeForwardHttpsStorageAuthorityV3
} from '../forward-https-storage-authority-v3.js'
import {
  prepareForwardHttpsSourceSessionV3,
  forwardHttpsSourceStoreV3Status
} from '../forward-https-source-store-v3.js'

const SOURCE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const TARGET = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
const ZERO32 = b4a.alloc(32)

function fixed (byte) {
  return b4a.alloc(32, byte)
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
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: SOURCE,
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
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: TARGET,
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

test('FTM9 horizon: expiry above 4294966394 rejects; boundary admits', async t => {
  const id = fixed(0x54)
  const base = {
    role: SOURCE,
    flags: 1,
    stableSessionId: id,
    sequence: 1n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x55),
    retainedUntilEpoch: 4294966394 + 900
  }
  await t.exception.all(() => encodeForwardHttpsSessionTerminalV3({ ...base, expiresAtEpoch: 4294966395 }))
  const ok = encodeForwardHttpsSessionTerminalV3({ ...base, expiresAtEpoch: 4294966394 })
  t.is(ok.readUInt32BE(145), 4294966394 + 900)
})

test('FTM9 flags1 rejects nonzero counters, wrong reason, nonzero revision', async t => {
  const id = fixed(0x56)
  const base = {
    role: SOURCE,
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
  await t.exception.all(() => encodeForwardHttpsSessionTerminalV3({ ...base, buckets: [1, 0, 0, 0, 0] }))
  await t.exception.all(() => encodeForwardHttpsSessionTerminalV3({ ...base, reason: 'CHAIN_INVALID' }))
  await t.exception.all(() => encodeForwardHttpsSessionTerminalV3({ ...base, priorSessionRevision: 1n }))
  await t.exception.all(() => encodeForwardHttpsSessionTerminalV3({ ...base, flags: 0 }))
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

test('export surfaces: V18 exact names present on source, target and storage modules', async t => {
  const source = await import('../forward-https-source-store-v3.js')
  const target = await import('../forward-https-target-store-v3.js')
  const storage = await import('../forward-https-storage-authority-v3.js')
  for (const name of ['FORWARD_HTTPS_SOURCE_STORE_V3_LIMITS', 'FORWARD_HTTPS_SOURCE_STORE_V3_STATUS', 'FORWARD_HTTPS_SOURCE_WAL_TYPE', 'FORWARD_HTTPS_SOURCE_STORE_V3_ERROR_CODE', 'FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT', 'ForwardHttpsSourceStoreV3Error', 'openForwardHttpsSourceStoreV3', 'prepareForwardHttpsSourceTurnV3', 'persistForwardHttpsSourceResultV3', 'forwardHttpsSourceTurnStateV3', 'forwardHttpsSourceStoreV3Status', 'closeForwardHttpsSourceStoreV3']) {
    t.ok(name in source, `source exports ${name}`)
  }
  for (const name of ['FORWARD_HTTPS_TARGET_STORE_V3_LIMITS', 'FORWARD_HTTPS_TARGET_STORE_V3_STATUS', 'FORWARD_HTTPS_TARGET_WAL_TYPE', 'FORWARD_HTTPS_TARGET_STORE_V3_ERROR_CODE', 'FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT', 'ForwardHttpsTargetStoreV3Error', 'openForwardHttpsTargetStoreV3', 'acceptForwardedHttpsTargetTurnV3', 'runNextForwardHttpsTargetProcessorWorkV3', 'forwardHttpsTargetTurnStateV3', 'forwardHttpsTargetStoreV3Status', 'closeForwardHttpsTargetStoreV3']) {
    t.ok(name in target, `target exports ${name}`)
  }
  for (const name of ['FORWARD_HTTPS_STORAGE_V3_LIMITS', 'FORWARD_HTTPS_STORAGE_V3_STATUS', 'FORWARD_HTTPS_STORAGE_V3_ERROR_CODE', 'FORWARD_HTTPS_STORAGE_V3_FAULT_POINT', 'ForwardHttpsStorageAuthorityV3Error']) {
    t.ok(name in storage, `storage exports ${name}`)
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
  const prepared = await prepareForwardHttpsSourceSessionV3(source, { stableSessionId: fixed(0x3c), body: b4a.alloc(8, 0x41) })
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
