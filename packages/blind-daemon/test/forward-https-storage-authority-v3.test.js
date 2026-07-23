import b4a from 'b4a'
import test from 'brittle'
import { blake2b256 } from '@hiverelay/blind-protocol'
import {
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3
} from '../forward-https-replay-journal-v4.js'
import {
  FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS,
  FORWARD_HTTPS_STORAGE_SLOT_STATE_V3,
  FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3,
  encodeForwardHttpsSessionTerminalV3,
  deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3,
  deriveForwardHttpsMinimalTerminalAuthorityClassesV3,
  createForwardHttpsChargeRegistryV3,
  streamForwardHttpsChargeCommitmentV3,
  verifyForwardHttpsTerminalHeadroomV3,
  verifyForwardHttpsTerminalInvarianceV3,
  checkForwardHttpsProtectedAdmissionV3,
  classifyForwardHttpsHistoricIdentityV3
} from '../forward-https-storage-authority-v3.js'

const SOURCE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const TARGET = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
const ZERO32 = b4a.alloc(32)

function fixed (byte) {
  return b4a.alloc(32, byte)
}

function derivedEntry (walType, sequence, hash, charge, id) {
  return {
    scope: 'SESSION',
    walType,
    walSequence: BigInt(sequence),
    payloadHash: hash,
    ordinaryLogicalCharge: charge,
    stableSessionId: id
  }
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
  const M = deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3({
    role: TARGET,
    stableSessionId: id,
    sequence: 11n,
    exactRequestCommitment: fixed(0x53),
    expiresAtEpoch,
    retainedUntilEpoch: expiresAtEpoch + 900,
    newTrustedEpochHighWatermark: 999,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID'
  })
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
  t.ok(b4a.equals(payload.subarray(149, 181), M))
  for (let index = 181; index < 192; index++) t.is(payload[index], 0)
  const classes = deriveForwardHttpsMinimalTerminalAuthorityClassesV3(M)
  t.is(classes.length, 10)
  for (let index = 0; index < 10; index++) {
    if (index === 7 || index === 9) t.absent(b4a.equals(classes[index], ZERO32))
    else t.ok(b4a.equals(classes[index], ZERO32))
  }
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

test('charge registry: 49-byte entries, streaming commitment parity, cap 65536 and 65537 INTEGRITY', async t => {
  const id = fixed(0x58)
  const registry = createForwardHttpsChargeRegistryV3(TARGET, id)
  const entries = []
  for (let index = 0; index < 65536; index++) {
    const hash = blake2b256(b4a.from([index & 0xff, (index >> 8) & 0xff]))
    const entry = registry.admit(derivedEntry(112, index + 1, hash, 460, id))
    t.is(entry.byteLength, 49)
    t.is(entry[0], 112)
    entries.push(entry)
  }
  t.is(registry.count, 65536)
  const streamed = streamForwardHttpsChargeCommitmentV3(TARGET, id, entries)
  t.is(streamed.count, 65536)
  t.ok(b4a.equals(registry.commitment(), streamed.commitment))
  await t.exception.all(() => registry.admit(derivedEntry(112, 65537, fixed(0x59), 460, id)))
  const over = [...entries, entries[0]]
  await t.exception.all(() => streamForwardHttpsChargeCommitmentV3(TARGET, id, over))
})

test('terminal headroom: production constants and test-open minimums', async t => {
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionHeadroomLogicalPerRole, 88080384)
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionHeadroomPhysicalPerRole, 58720256)
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionHeadroomLogicalAggregate, 176160768)
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionHeadroomPhysicalAggregate, 117440512)
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionOrdinaryLogicalCeilingPerStoreAtFreshRoot, 8501854208)
  t.is(FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS.productionOrdinaryPhysicalCeilingPerStoreAtFreshRoot, 8531214336)
  const production = verifyForwardHttpsTerminalHeadroomV3({
    capacity: 65536,
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184
  })
  t.is(production.headroomLogicalPerRole, 88080384)
  t.is(production.ordinaryLogicalCeilingPerStore, 8589934592 - 88080384)
  t.is(production.ordinaryPhysicalCeilingPerStore, 8589934592 - 58720256)
  const capacity = 8
  await t.exception.all(() => verifyForwardHttpsTerminalHeadroomV3({
    capacity,
    maximumDurableBytesPerStore: capacity * 1344 - 1,
    maximumForwardStorageBytesAggregate: 2 * capacity * 1344
  }))
  const reduced = verifyForwardHttpsTerminalHeadroomV3({
    capacity,
    maximumDurableBytesPerStore: capacity * 1344,
    maximumForwardStorageBytesAggregate: 2 * capacity * 1344
  })
  t.is(reduced.ordinaryLogicalCeilingPerStore, 0)
})

test('terminal invariance: protected sum unchanged, liability reduced 608/416', async t => {
  const result = verifyForwardHttpsTerminalInvarianceV3(10, 2)
  t.ok(result.protectedSumInvariant)
  t.is(result.logicalReduction, 608)
  t.is(result.physicalReduction, 416)
  await t.exception.all(() => verifyForwardHttpsTerminalInvarianceV3(0, 0))
})

test('protected admission: equality admits, plus one fails', async t => {
  const base = {
    role: 'SOURCE_STORE',
    currentSourceLogical: 1000,
    currentTargetLogical: 0,
    currentSourcePhysical: 1448,
    currentTargetPhysical: 0,
    currentReplayPhysical: 0,
    plannedOrdinaryLogical: 0,
    plannedOrdinaryPhysical: 0,
    sourceUnconsumedSlots: 1,
    targetUnconsumedSlots: 1,
    sourceConsumedUnprunedSlots: 0,
    targetConsumedUnprunedSlots: 0,
    maximumDurableBytesPerStore: 1000 + 1344,
    maximumForwardStorageBytesAggregate: 1000 + 2 * 1344
  }
  t.ok(checkForwardHttpsProtectedAdmissionV3(base), 'exact equality admits')
  t.absent(checkForwardHttpsProtectedAdmissionV3({ ...base, plannedOrdinaryLogical: 1 }), 'one byte over fails')
  t.absent(checkForwardHttpsProtectedAdmissionV3({ ...base, plannedOrdinaryPhysical: 1 }), 'physical one byte over fails')
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

test('historic identity states classify exactly', async t => {
  t.is(Object.keys(FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3).length, 7)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.NEVER_SEEN)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_PREFIX_ALLOCATED)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.ALLOCATED_WITH_PREFIX)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_ALLOCATED)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PROVISIONAL, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_ALLOCATED)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED, false), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_CONSUMED_UNPRUNED)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE, true), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRUNED_RELEASED)
  t.is(classifyForwardHttpsHistoricIdentityV3(FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED, true), FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRUNED_CONSUMED)
})
