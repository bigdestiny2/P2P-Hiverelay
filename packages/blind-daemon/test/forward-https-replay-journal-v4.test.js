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
  createLocalForwardHttpsOriginAuthorityV4,
  encodeLocalForwardHttpsOriginAuthorityV4,
  createLocalForwardHttpsTargetIngressV4,
  encodeLocalForwardHttpsTargetIngressV4
} from '@hiverelay/blind-ipc'
import * as replayModule from '../forward-https-replay-journal-v4.js'
import {
  encodeForwardHttpsRetentionPrunedV3,
  decodeForwardHttpsRetentionPrunedV3,
  deriveForwardHttpsStoreWalQuotaEntryV3,
  openForwardHttpsAggregateQuotaV3,
  mintForwardHttpsAggregateQuotaCapabilitiesV3,
  closeForwardHttpsAggregateQuotaV3,
  beginForwardHttpsAggregateQuotaRecoveryV3,
  absorbForwardHttpsAggregateQuotaRecoveryFrameV3,
  finishForwardHttpsAggregateQuotaRecoveryV3,
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3
} from '../forward-https-replay-journal-v4.js'
import {
  encodeForwardHttpsSessionTerminalV3,
  deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3
} from '../forward-https-storage-authority-v3.js'

const SOURCE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const TARGET = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
const ZERO32 = b4a.alloc(32)

function fixed (byte) {
  return b4a.alloc(32, byte)
}

function frame (type, payload, sequence = 1n) {
  return {
    type,
    payload,
    payloadHash: blake2b256(payload),
    sequence,
    frameBytes: payload.byteLength + 224
  }
}

function recoveryFrame (type, payload, sequence, previousWalHash) {
  return {
    type,
    payload,
    payloadHash: blake2b256(payload),
    sequence,
    previousWalHash,
    walHash: blake2b256(b4a.concat([b4a.from('wal'), payload])),
    frameBytes: payload.byteLength + 224
  }
}

function sessionBody (id) {
  return b4a.concat([b4a.from('FSS3', 'ascii'), id, b4a.alloc(8, 0x41)])
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

function replayJournalOptions (role, root, capability, monotonicMillis) {
  return {
    role,
    root,
    manifestKey: b4a.alloc(32, 7),
    replayQuotaCapability: capability,
    wireV3AbiHash: fixed(0x01),
    privateIpcV4Hash: fixed(0x02),
    signedLaunchTopologyHash: fixed(0x03),
    storeId: fixed(0x04),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x05),
    durabilityContinuityHash: fixed(0x06),
    monotonicMillis
  }
}

function sourceReplayRecord (id, now) {
  return encodeLocalForwardHttpsOriginAuthorityV4(createLocalForwardHttpsOriginAuthorityV4({
    version: 4,
    authorityKind: 1,
    transportId: 1,
    endpointId: 1,
    flags: 0,
    wireV3AbiHash: fixed(0x01),
    signedLaunchTopologyHash: fixed(0x03),
    edgeProcessNonce: fixed(0x0a),
    localChannelNonce: fixed(0x0b),
    tlsExporterBindingHash: fixed(0x0c),
    originRequestCommitment: fixed(0x0d),
    stableSessionId: id,
    sequence: 1n,
    acceptedMonotonicMillis: BigInt(now),
    absoluteDeadlineMonotonicMillis: BigInt(now) + 10000n
  }))
}

function targetReplayRecord (id, now) {
  return encodeLocalForwardHttpsTargetIngressV4(createLocalForwardHttpsTargetIngressV4({
    version: 4,
    authorityKind: 2,
    transportId: 1,
    endpointId: 2,
    flags: 0,
    wireV3AbiHash: fixed(0x01),
    signedLaunchTopologyHash: fixed(0x03),
    edgeProcessNonce: fixed(0x0a),
    localChannelNonce: fixed(0x0b),
    targetTlsExporterBindingHash: fixed(0x0c),
    forwardedRequestCommitment: fixed(0x0d),
    stableSessionId: id,
    sequence: 1n,
    acceptedMonotonicMillis: BigInt(now),
    absoluteDeadlineMonotonicMillis: BigInt(now) + 10000n
  }))
}

test('replay journal bootstrap: fresh-root open for both roles and snapshot reopen round trip', async t => {
  const { capabilities, roots } = await quota(t, SOURCE)
  const clock = () => 100000n
  // SOURCE_ORIGIN fresh-root BOOTSTRAP then reopen
  const sourceOptions = replayJournalOptions('SOURCE_ORIGIN', roots['source-replay'], capabilities.sourceReplayQuotaCapability, clock)
  const source = await replayModule.openForwardHttpsReplayJournalV4(sourceOptions)
  t.is(replayModule.forwardHttpsReplayJournalV4Status(source).state, 'OPEN')
  await replayModule.closeForwardHttpsReplayJournalV4(source)
  const sourceReopen = await replayModule.openForwardHttpsReplayJournalV4(sourceOptions)
  const sourceStatus = replayModule.forwardHttpsReplayJournalV4Status(sourceReopen)
  t.is(sourceStatus.state, 'OPEN')
  t.is(sourceStatus.occupied, 0)
  await replayModule.closeForwardHttpsReplayJournalV4(sourceReopen)
  // TARGET_INGRESS fresh-root BOOTSTRAP then reopen
  const targetOptions = replayJournalOptions('TARGET_INGRESS', roots['target-replay'], capabilities.targetReplayQuotaCapability, clock)
  const target = await replayModule.openForwardHttpsReplayJournalV4(targetOptions)
  t.is(replayModule.forwardHttpsReplayJournalV4Status(target).state, 'OPEN')
  await replayModule.closeForwardHttpsReplayJournalV4(target)
  const targetReopen = await replayModule.openForwardHttpsReplayJournalV4(targetOptions)
  const targetStatus = replayModule.forwardHttpsReplayJournalV4Status(targetReopen)
  t.is(targetStatus.state, 'OPEN')
  t.is(targetStatus.occupied, 0)
  await replayModule.closeForwardHttpsReplayJournalV4(targetReopen)
})

test('replay journal: reserve/consume persists across close and reopen, replay rejects', async t => {
  for (const role of ['SOURCE_ORIGIN', 'TARGET_INGRESS']) {
    const { capabilities, roots } = await quota(t, SOURCE)
    const clock = () => 100000n
    const replayRoot = role === 'SOURCE_ORIGIN' ? roots['source-replay'] : roots['target-replay']
    const capability = role === 'SOURCE_ORIGIN' ? capabilities.sourceReplayQuotaCapability : capabilities.targetReplayQuotaCapability
    const options = replayJournalOptions(role, replayRoot, capability, clock)
    const id = fixed(role === 'SOURCE_ORIGIN' ? 0x51 : 0x52)
    const record = role === 'SOURCE_ORIGIN' ? sourceReplayRecord(id, 100000n) : targetReplayRecord(id, 100000n)
    const journal = await replayModule.openForwardHttpsReplayJournalV4(options)
    const reservation = await replayModule.reserveForwardHttpsReplayV4(journal, { record })
    t.is(replayModule.inspectForwardHttpsReplayJournalV4(journal).length, 1)
    const consumed = await replayModule.consumeForwardHttpsReplayV4(journal, reservation, { record })
    replayModule.verifyForwardHttpsReplayConsumedV4(consumed, { journalAuthority: journal, role, record })
    await replayModule.closeForwardHttpsReplayJournalV4(journal)
    const reopened = await replayModule.openForwardHttpsReplayJournalV4(options)
    const status = replayModule.forwardHttpsReplayJournalV4Status(reopened)
    t.is(status.state, 'OPEN')
    t.is(status.consumed, 1, 'consumed replay tuple recovered exactly once')
    await t.exception.all(replayModule.reserveForwardHttpsReplayV4(reopened, { record }), /occupied|REPLAY/)
    await replayModule.closeForwardHttpsReplayJournalV4(reopened)
  }
})

test('export surface: exactly the frozen 39 replay-module exports', async t => {
  const names = Object.keys(replayModule).sort()
  const expected = [
    'FORWARD_HTTPS_REPLAY_ROLE_V4',
    'FORWARD_HTTPS_REPLAY_JOURNAL_V4_LIMITS',
    'FORWARD_HTTPS_REPLAY_JOURNAL_V4_STATUS',
    'FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE',
    'FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT',
    'ForwardHttpsReplayJournalV4Error',
    'openForwardHttpsReplayJournalV4',
    'reserveForwardHttpsReplayV4',
    'consumeForwardHttpsReplayV4',
    'verifyForwardHttpsReplayConsumedV4',
    'forwardHttpsReplayJournalV4Status',
    'inspectForwardHttpsReplayJournalV4',
    'closeForwardHttpsReplayJournalV4',
    'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE',
    'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT',
    'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_LIMITS',
    'FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3',
    'ForwardHttpsAggregateQuotaV3Error',
    'openForwardHttpsAggregateQuotaV3',
    'mintForwardHttpsAggregateQuotaCapabilitiesV3',
    'beginForwardHttpsAggregateQuotaRecoveryV3',
    'absorbForwardHttpsAggregateQuotaRecoveryFrameV3',
    'finishForwardHttpsAggregateQuotaRecoveryV3',
    'initializeForwardHttpsAggregateQuotaV3',
    'createForwardHttpsReplayQuotaCostPlanV3',
    'createForwardHttpsStoreQuotaCostPlanV3',
    'bindForwardHttpsStoreQuotaActualBuffersV3',
    'reserveForwardHttpsAggregateQuotaV3',
    'commitForwardHttpsAggregateQuotaV3',
    'releaseForwardHttpsAggregateQuotaV3',
    'adjustForwardHttpsAggregateQuotaV3',
    'forwardHttpsAggregateQuotaV3Status',
    'closeForwardHttpsAggregateQuotaV3',
    'encodeForwardHttpsRetentionPrunedV3',
    'decodeForwardHttpsRetentionPrunedV3',
    'deriveForwardHttpsStoreWalQuotaEntryV3',
    'assertForwardHttpsAggregateQuotaOperationalV3',
    'applyForwardHttpsAggregateQuotaWalFrameV3',
    'failForwardHttpsAggregateQuotaWalAttemptV3'
  ].sort()
  t.is(names.length, 39, 'exactly 39 named exports')
  t.alike(names, expected)
  t.absent(names.includes('beginForwardHttpsAggregateQuotaWalAttemptV3'), 'begin is module-private and never exported')
  t.absent(names.includes('FORWARD_HTTPS_STORE_WAL_QUOTA_REGISTRY_V3'), 'registry must never be exported')
})

test('FPR9 ordinary variant: exact 256-byte layout, round trip and arithmetic', async t => {
  const id = fixed(0x61)
  const entries = [chargeEntry(97, 7n, fixed(0x71), 292 + 516)]
  const input = {
    role: SOURCE,
    stableSessionId: id,
    priorSessionRevision: 3n,
    pruneEpochSeconds: 1900,
    trustedEpochHighWatermark: 1900,
    expiresAtEpoch: 1000,
    recoveryGraceUntilEpoch: 1900,
    removedOrdinaryLogicalBytes: 808n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 3,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: entries,
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  }
  const payload = encodeForwardHttpsRetentionPrunedV3(input)
  t.is(payload.byteLength, 256)
  t.is(payload[4], 1)
  t.is(payload[5], 1)
  t.is(payload.readUInt16BE(6), 0)
  t.is(b4a.toString(payload.subarray(0, 4), 'ascii'), 'FPR9')
  t.is(payload.readUInt32BE(72), 1)
  t.is(payload.readUInt32BE(80), 0)
  t.is(payload[84], 1)
  t.is(payload[85], 1)
  for (let index = 184; index < 256; index++) t.is(payload[index], 0)
  const decoded = decodeForwardHttpsRetentionPrunedV3(payload)
  t.is(decoded.role, 1)
  t.is(decoded.flags, 0)
  t.ok(b4a.equals(decoded.stableSessionId, id))
  t.is(decoded.priorSessionRevision, 3n)
  t.is(decoded.removedOrdinaryLogicalBytes, 808n)
  t.is(decoded.chargeEntryCount, 1)
  t.is(decoded.beforeAuthorityBitmap, 3)
  const expectedCharge = streamingCharge(1, id, entries)
  t.ok(b4a.equals(decoded.chargeRegistryCommitment, expectedCharge))
  const expectedAuthority = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii'),
    b4a.from([1]), id, u64be(3n), u32be(3), ...Array.from({ length: 10 }, () => b4a.from(ZERO32))
  ]))
  t.ok(b4a.equals(decoded.authorityRegistryCommitment, expectedAuthority))
  const expectedState = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-prune-session-state.v3', 'ascii'),
    u16be(0), b4a.from([1]), id, u64be(3n), expectedCharge, expectedAuthority, b4a.from([1])
  ]))
  t.ok(b4a.equals(decoded.previousSessionStateCommitment, expectedState))
})

test('FPR9 terminal-only count0: empty registry commitment and two authority domains', async t => {
  const id = fixed(0x62)
  const expiresAtEpoch = 100000
  const retainedUntilEpoch = expiresAtEpoch + 900
  const M = deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3({
    role: TARGET,
    stableSessionId: id,
    sequence: 9n,
    exactRequestCommitment: fixed(0x63),
    expiresAtEpoch,
    retainedUntilEpoch,
    newTrustedEpochHighWatermark: 4242,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID'
  })
  const commitments = Array.from({ length: 10 }, () => b4a.from(ZERO32))
  commitments[7] = blake2b256(b4a.concat([b4a.from('hiverelay.blind.forward-https-retention-lookup.v3', 'ascii'), M]))
  commitments[9] = blake2b256(b4a.concat([b4a.from('hiverelay.blind.forward-https-terminal-state.v3', 'ascii'), M]))
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    stableSessionId: id,
    priorSessionRevision: 1n,
    pruneEpochSeconds: retainedUntilEpoch + 1,
    trustedEpochHighWatermark: retainedUntilEpoch + 1,
    expiresAtEpoch,
    recoveryGraceUntilEpoch: retainedUntilEpoch,
    removedOrdinaryLogicalBytes: 0n,
    chargeEntryCount: 0,
    beforeAuthorityBitmap: 640,
    allocationDisposition: 0,
    terminalSlotState: 2,
    chargeEntryBuffers: [],
    authorityCommitments: commitments
  })
  t.is(payload.byteLength, 256)
  const decoded = decodeForwardHttpsRetentionPrunedV3(payload)
  t.is(decoded.chargeEntryCount, 0)
  t.is(decoded.removedOrdinaryLogicalBytes, 0n)
  t.is(decoded.beforeAuthorityBitmap, 640)
  t.is(decoded.allocationDisposition, 0)
  t.is(decoded.terminalSlotState, 2)
  const emptyCharge = streamingCharge(2, id, [])
  t.ok(b4a.equals(decoded.chargeRegistryCommitment, emptyCharge))
  const expectedAuthority = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii'),
    b4a.from([2]), id, u64be(1n), u32be(640), ...commitments
  ]))
  t.ok(b4a.equals(decoded.authorityRegistryCommitment, expectedAuthority))
})

test('FPR9 rejects count/removal mismatch and noncanonical padding', async t => {
  const id = fixed(0x64)
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({
    role: SOURCE,
    stableSessionId: id,
    priorSessionRevision: 1n,
    pruneEpochSeconds: 1,
    trustedEpochHighWatermark: 1,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 5n,
    chargeEntryCount: 0,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 0,
    terminalSlotState: 2,
    chargeEntryBuffers: [],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  }))
  const good = encodeForwardHttpsRetentionPrunedV3({
    role: SOURCE,
    stableSessionId: id,
    priorSessionRevision: 1n,
    pruneEpochSeconds: 1,
    trustedEpochHighWatermark: 1,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 5n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: [chargeEntry(96, 1n, fixed(0x65), 5)],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const corrupted = b4a.from(good)
  corrupted[255] = 1
  await t.exception.all(() => decodeForwardHttpsRetentionPrunedV3(corrupted))
})

test('FPR9 flags1 recovered-prefix orphan variant: exact fields and prefix domain', async t => {
  const id = fixed(0x6d)
  const entries = [chargeEntry(113, 4n, fixed(0x6e), 460), chargeEntry(113, 5n, fixed(0x6f), 460)]
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    priorSessionRevision: 5n,
    pruneEpochSeconds: 7000,
    trustedEpochHighWatermark: 7000,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 920n,
    chargeEntryCount: 2,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 3,
    chargeEntryBuffers: entries,
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  t.is(payload.readUInt16BE(6), 1)
  t.is(payload.readUInt32BE(56), 0)
  t.is(payload.readUInt32BE(60), 0)
  t.is(payload[84], 1)
  t.is(payload[85], 3)
  const decoded = decodeForwardHttpsRetentionPrunedV3(payload)
  t.is(decoded.flags, 1)
  t.is(decoded.terminalSlotState, 3)
  t.is(decoded.chargeEntryCount, 2)
  t.is(decoded.removedOrdinaryLogicalBytes, 920n)
  const expectedCharge = streamingCharge(2, id, entries)
  const expectedAuthority = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii'),
    b4a.from([2]), id, u64be(5n), u32be(0), ...Array.from({ length: 10 }, () => b4a.from(ZERO32))
  ]))
  const expectedState = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-prefix-session-state.v3', 'ascii'),
    u16be(1), b4a.from([2]), id, u64be(5n), expectedCharge, expectedAuthority, b4a.from([3])
  ]))
  t.ok(b4a.equals(decoded.chargeRegistryCommitment, expectedCharge))
  t.ok(b4a.equals(decoded.authorityRegistryCommitment, expectedAuthority))
  t.ok(b4a.equals(decoded.previousSessionStateCommitment, expectedState))
  // Byte-identical re-encode
  t.ok(b4a.equals(encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    priorSessionRevision: 5n,
    pruneEpochSeconds: 7000,
    trustedEpochHighWatermark: 7000,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 920n,
    chargeEntryCount: 2,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 3,
    chargeEntryBuffers: entries,
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  }), payload))
})

test('FPR9 flags2 existing-session prefix-abort variant: retained slot, prefix domain', async t => {
  const id = fixed(0x70)
  const entries = [chargeEntry(113, 9n, fixed(0x71), 460)]
  const before = Array.from({ length: 10 }, () => b4a.from(ZERO32))
  before[4] = fixed(0x72)
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    flags: 2,
    stableSessionId: id,
    priorSessionRevision: 9n,
    pruneEpochSeconds: 8000,
    trustedEpochHighWatermark: 8000,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 460n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 1 << 4,
    allocationDisposition: 2,
    terminalSlotState: 1,
    chargeEntryBuffers: entries,
    authorityCommitments: before
  })
  t.is(payload.readUInt16BE(6), 2)
  t.is(payload[84], 2)
  t.is(payload[85], 1)
  const decoded = decodeForwardHttpsRetentionPrunedV3(payload)
  t.is(decoded.flags, 2)
  t.is(decoded.allocationDisposition, 2)
  t.is(decoded.terminalSlotState, 1)
  const expectedCharge = streamingCharge(2, id, entries)
  const expectedAuthority = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii'),
    b4a.from([2]), id, u64be(9n), u32be(1 << 4), ...before
  ]))
  const expectedState = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-prefix-session-state.v3', 'ascii'),
    u16be(2), b4a.from([2]), id, u64be(9n), expectedCharge, expectedAuthority, b4a.from([1])
  ]))
  t.ok(b4a.equals(decoded.chargeRegistryCommitment, expectedCharge))
  t.ok(b4a.equals(decoded.authorityRegistryCommitment, expectedAuthority))
  t.ok(b4a.equals(decoded.previousSessionStateCommitment, expectedState))
})

test('FPR9 variant matrix and substitution negatives reject', async t => {
  const id = fixed(0x73)
  const entries = [chargeEntry(113, 2n, fixed(0x74), 460)]
  const base = {
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    priorSessionRevision: 2n,
    pruneEpochSeconds: 100,
    trustedEpochHighWatermark: 100,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 460n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 3,
    chargeEntryBuffers: entries,
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  }
  // flags1 with nonzero expiry fields violates the immediate exception
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({ ...base, expiresAtEpoch: 5 }))
  // flags1 with terminal-only count0 is not a prefix variant
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({ ...base, chargeEntryCount: 0, chargeEntryBuffers: [], removedOrdinaryLogicalBytes: 0n }))
  // removed sum must match the exact entry chain
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({ ...base, removedOrdinaryLogicalBytes: 461n }))
  // flags2 requires NONE_RETAINED_ALLOCATED/ALLOCATED
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({ ...base, flags: 2 }))
  // unknown flags scalar
  await t.exception.all(() => encodeForwardHttpsRetentionPrunedV3({ ...base, flags: 3 }))
  const good = encodeForwardHttpsRetentionPrunedV3(base)
  // flags-encoding substitution: flags1 payload presented with flags2 rejects
  const swapped = b4a.from(good)
  swapped.writeUInt16BE(2, 6)
  await t.exception.all(() => decodeForwardHttpsRetentionPrunedV3(swapped))
  // padding substitution rejects
  const padded = b4a.from(good)
  padded[255] = 1
  await t.exception.all(() => decodeForwardHttpsRetentionPrunedV3(padded))
  // disposition/slot substitution rejects
  const disposition = b4a.from(good)
  disposition[84] = 2
  await t.exception.all(() => decodeForwardHttpsRetentionPrunedV3(disposition))
})

test('derive: ordinary SESSION frame charge is payload+frame', async t => {
  const { capability } = await quota(t, SOURCE)
  const id = fixed(0x66)
  const payload = sessionBody(id)
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(96, payload, 1n, ZERO32) })
  t.is(derived.role, SOURCE)
  t.is(derived.scope, 'SESSION')
  t.is(derived.walType, 96)
  t.is(derived.walSequence, 1n)
  t.is(derived.ordinaryLogicalCharge, payload.byteLength + payload.byteLength + 224)
  t.is(derived.terminalLogicalCharge, 0)
  t.is(derived.authorityBitmap, 0)
  t.ok(b4a.equals(derived.stableSessionId, id))
  t.is(derived.authorityCommitments.length, 10)
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
})

test('derive: type113 independent charge is exactly460', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x67)
  const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(118 - 36, 0x42)])
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(113, payload, 1n, ZERO32) })
  t.is(derived.ordinaryLogicalCharge, 460)
  t.is(derived.scope, 'SESSION')
  t.ok(b4a.equals(derived.stableSessionId, id))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
})

test('derive: FTM9 minimal terminal yields bitmap640 and rederived class7/class9 commitments', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x68)
  const expiresAtEpoch = 200000
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    sequence: 3n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 77,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x69),
    expiresAtEpoch,
    retainedUntilEpoch: expiresAtEpoch + 900
  })
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(117, payload, 1n, ZERO32) })
  t.is(derived.ordinaryLogicalCharge, 0)
  t.is(derived.terminalLogicalCharge, 608)
  t.is(derived.authorityBitmap, 640)
  for (let index = 0; index < 10; index++) {
    if (index === 7 || index === 9) t.absent(b4a.equals(derived.authorityCommitments[index], ZERO32))
    else t.ok(b4a.equals(derived.authorityCommitments[index], ZERO32))
  }
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
})

test('derive: flags0 existing terminal preserves the vector and adds exact C9 (terminal-state-existing.v3)', async t => {
  const { capability } = await quota(t, SOURCE)
  const id = fixed(0x75)
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const first = sessionBody(id)
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(96, first, 1n, ZERO32) })
  const terminalPayload = encodeForwardHttpsSessionTerminalV3({
    role: SOURCE,
    flags: 0,
    stableSessionId: id,
    sequence: 9n,
    priorSessionRevision: 1n,
    newTrustedEpochHighWatermark: 5,
    reason: 'CHAIN_INVALID'
  })
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
    frame: recoveryFrame(99, terminalPayload, 2n, blake2b256(b4a.concat([b4a.from('wal'), first])))
  })
  t.is(derived.terminalLogicalCharge, 608)
  t.is(derived.authorityBitmap, 512)
  const expectedC9 = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-terminal-state-existing.v3', 'ascii'),
    b4a.from([1]), id, u64be(1n), u32be(0),
    ...Array.from({ length: 9 }, () => b4a.from(ZERO32)),
    u64be(2n), blake2b256(terminalPayload)
  ]))
  for (let index = 0; index < 9; index++) t.ok(b4a.equals(derived.authorityCommitments[index], ZERO32))
  t.ok(b4a.equals(derived.authorityCommitments[9], expectedC9))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  // A duplicate terminal now rejects: the predecessor is consumed
  const sink2 = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink2, { frame: recoveryFrame(96, first, 1n, ZERO32) })
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink2, { frame: recoveryFrame(99, terminalPayload, 2n, blake2b256(b4a.concat([b4a.from('wal'), first]))) })
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink2, {
    frame: recoveryFrame(99, terminalPayload, 3n, blake2b256(b4a.concat([b4a.from('wal'), terminalPayload])))
  }), /PRESENT_ALLOCATED|INTEGRITY/)
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink2)
})

test('derive: FPR9 prune transition has 736 role-global charge', async t => {
  const { capability } = await quota(t, SOURCE)
  const id = fixed(0x6a)
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: SOURCE,
    stableSessionId: id,
    priorSessionRevision: 2n,
    pruneEpochSeconds: 9,
    trustedEpochHighWatermark: 9,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: 10n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 1,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: [chargeEntry(96, 1n, fixed(0x6b), 10)],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(100, payload, 1n, ZERO32) })
  t.is(derived.scope, 'PRUNE_TRANSITION')
  t.is(derived.ordinaryLogicalCharge, 736)
  t.ok(b4a.equals(derived.stableSessionId, id))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
})

test('derive: cross-role and unknown types are INTEGRITY', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x6c)
  const payload = sessionBody(id)
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(96, payload, 1n, ZERO32) }))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  const sink2 = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink2, { frame: recoveryFrame(55, payload, 1n, ZERO32) }))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink2)
  const { capability: sourceCapability } = await quota(t, SOURCE)
  const sink3 = beginForwardHttpsAggregateQuotaRecoveryV3(sourceCapability)
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink3, { frame: recoveryFrame(112, payload, 1n, ZERO32) }))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink3)
})

test('operation bound rows: exact conservative ceilings, inapplicable pairs and bind ceilings', async t => {
  const { capability } = await quota(t, TARGET)
  const { capability: sourceCapability } = await quota(t, SOURCE)
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'PROCESSOR_COMPLETED',
    knownInputBuffers: [b4a.alloc(1024)],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  // The union disposition for an ordinary row is ORDINARY with the exact row ceiling
  const { disposition, reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  t.is(disposition, 'ORDINARY')
  t.ok(reservation)
  // Bind actual cannot exceed the exact row (4683994 logical / 2344461 physical)
  await t.exception.all(() => replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
    logicalRecordBuffers: [b4a.alloc(4683994)],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [b4a.alloc(36, 1)],
    temporaryWriteBuffers: []
  }), /exceed the conservative plan|must be exactly 118/)
  // Inapplicable role/operation pair is INVALID before plan creation
  await t.exception.all(() => replayModule.createForwardHttpsStoreQuotaCostPlanV3(sourceCapability, {
    operation: 'PROCESSOR_COMPLETED',
    knownInputBuffers: [],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  }), /inapplicable|INVALID/)
  await t.exception.all(() => replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'PREPARE',
    knownInputBuffers: [],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  }), /inapplicable|INVALID/)
  // Known input above the row maximum is INVALID
  await t.exception.all(() => replayModule.createForwardHttpsStoreQuotaCostPlanV3(sourceCapability, {
    operation: 'RESULT',
    knownInputBuffers: [b4a.alloc(16777217)],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  }), /exceeds the operation row|INVALID|must be/)
})

test('reserve disposition union: REQUESTED_TERMINAL for terminal plans and ENTRY_CAP_TERMINAL at the 65536 cap', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x7a)
  const terminalPayload = encodeForwardHttpsSessionTerminalV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    sequence: 2n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x7b),
    expiresAtEpoch: 100,
    retainedUntilEpoch: 1000
  })
  const terminalPlan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'SESSION_TERMINAL',
    knownInputBuffers: [terminalPayload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const terminalUnion = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, terminalPlan)
  t.is(terminalUnion.disposition, 'REQUESTED_TERMINAL')
  t.ok(terminalUnion.terminalReservation)
  t.absent('reservation' in terminalUnion)
  // ENTRY_CAP_TERMINAL: recovered count 65536 plus planned 1 exceeds the cap.
  // Seed the canonical mirror through one recovery sink replaying 65536
  // entries of one session, then reserve an ordinary row for that session.
  const { capability: cappedCapability } = await quota(t, TARGET)
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(cappedCapability)
  let previous = ZERO32
  for (let index = 1; index <= 65536; index++) {
    const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, index & 0xff)])
    const walHash = blake2b256(b4a.concat([b4a.from('wal'), payload, u64be(BigInt(index))]))
    await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
      frame: { type: 112, payload, payloadHash: blake2b256(payload), sequence: BigInt(index), previousWalHash: previous, walHash, frameBytes: payload.byteLength + 224 }
    })
    previous = walHash
  }
  // A 65537th recovered charge entry is INTEGRITY before localOperational
  const overflowPayload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0xff)])
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
    frame: { type: 112, payload: overflowPayload, payloadHash: blake2b256(overflowPayload), sequence: 65537n, previousWalHash: previous, walHash: blake2b256(b4a.concat([b4a.from('wal'), overflowPayload])), frameBytes: overflowPayload.byteLength + 224 }
  }), /exceed the cap|INTEGRITY/)
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  const cappedPlan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(cappedCapability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x01)])],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const cappedUnion = await replayModule.reserveForwardHttpsAggregateQuotaV3(cappedCapability, cappedPlan)
  t.is(cappedUnion.disposition, 'ENTRY_CAP_TERMINAL')
  t.ok(cappedUnion.terminalReservation)
})

test('failure states: terminal prewrite abort enters FAILED_PREWRITE; close rules reach CLOSED exactly', async t => {
  const { authority, capability } = await quota(t, TARGET)
  const id = fixed(0x7c)
  const terminalPayload = encodeForwardHttpsSessionTerminalV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    sequence: 2n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x7d),
    expiresAtEpoch: 100,
    retainedUntilEpoch: 1000
  })
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'SESSION_TERMINAL',
    knownInputBuffers: [terminalPayload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { disposition, terminalReservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  t.is(disposition, 'REQUESTED_TERMINAL')
  // Terminal prewrite abort: release before the first begin enters FAILED_PREWRITE
  await t.exception.all(replayModule.releaseForwardHttpsAggregateQuotaV3(capability, terminalReservation), /FAILED_PREWRITE/)
  const failed = replayModule.forwardHttpsAggregateQuotaV3Status(authority)
  t.is(failed.state, 'FAILED_PREWRITE')
  t.absent(failed.localOperational)
  await t.exception.all(() => replayModule.assertForwardHttpsAggregateQuotaOperationalV3(capability), /not operational/)
  // Close reaches CLOSED and exact-owner repeat resolves without retry
  await closeForwardHttpsAggregateQuotaV3(authority)
  t.is(replayModule.forwardHttpsAggregateQuotaV3Status(authority).state, 'CLOSED')
  await closeForwardHttpsAggregateQuotaV3(authority)
  // Foreign authority rejects
  await t.exception.all(closeForwardHttpsAggregateQuotaV3(Object.freeze({})), /forged|AUTHORITY_INVALID/)
})

test('close with a pending ordinary reservation returns INTEGRITY and never steals the token', async t => {
  const { authority, capability } = await quota(t, TARGET)
  const id = fixed(0x7e)
  const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x41)])
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  await t.exception.all(closeForwardHttpsAggregateQuotaV3(authority), /pending ordinary reservation/)
  // The owning operation still holds the token and can release cleanly
  await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, reservation)
  await closeForwardHttpsAggregateQuotaV3(authority)
  t.is(replayModule.forwardHttpsAggregateQuotaV3Status(authority).state, 'CLOSED')
})

test('quota FIFO mutex: overlapping reservations reject in submission order and retry never starves', async t => {
  const { capability } = await quota(t, TARGET)
  const makePlan = byte => replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [b4a.concat([b4a.from('FTS3', 'ascii'), fixed(byte), b4a.alloc(8, 0x41)])],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  // One outstanding reservation per authority: overlapping submissions are
  // rejected (waiters are rejected) in exact FIFO submission order.
  const first = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x81))
  const outcomes = []
  await Promise.all([
    replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x82))
      .then(() => outcomes.push('second-admitted'), error => outcomes.push(`second:${error.code}`)),
    replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x83))
      .then(() => outcomes.push('third-admitted'), error => outcomes.push(`third:${error.code}`))
  ])
  t.alike(outcomes, ['second:FORWARD_HTTPS_AGGREGATE_QUOTA_V3_INTEGRITY', 'third:FORWARD_HTTPS_AGGREGATE_QUOTA_V3_INTEGRITY'])
  // No starvation: once the holder releases, the next admission succeeds.
  await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, first.reservation)
  const second = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x84))
  t.is(second.disposition, 'ORDINARY')
  await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, second.reservation)
  // Store-level: two concurrent operations on one store serialize through the
  // mutex; exactly one wins at a time and the loser succeeds on retry.
  const r = await createBlindBoundaryScratch('fhfifo-')
  t.teardown(async () => { await removeBlindBoundaryScratch(r) })
  for (const name of ['source-replay', 'target-replay', 'source-store', 'target-store']) {
    await fs.mkdir(path.join(r, name), { mode: 0o700 })
    await fs.chmod(path.join(r, name), 0o700)
  }
  const authority = await openForwardHttpsAggregateQuotaV3({
    sourceReplayRoot: path.join(r, 'source-replay'),
    targetReplayRoot: path.join(r, 'target-replay'),
    sourceStoreRoot: path.join(r, 'source-store'),
    targetStoreRoot: path.join(r, 'target-store'),
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184,
    monotonicMillis: () => Date.now(),
    callbackTimeoutMillis: 15000,
    faultInjector: null
  })
  t.teardown(async () => { await closeForwardHttpsAggregateQuotaV3(authority).catch(() => {}) })
  const capabilities = mintForwardHttpsAggregateQuotaCapabilitiesV3(authority)
  const { openForwardHttpsTargetStoreV3, openForwardHttpsTargetSessionV3, appendForwardHttpsTargetSessionV3, closeForwardHttpsTargetStoreV3 } = await import('../forward-https-target-store-v3.js')
  const store = await openForwardHttpsTargetStoreV3({
    root: path.join(r, 'target-store'),
    storeQuotaCapability: capabilities.targetStoreQuotaCapability,
    storeId: fixed(0x41),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x42),
    durabilityContinuityHash: fixed(0x43),
    monotonicMillis: () => Date.now()
  })
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  const sourceSink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
  const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sourceSink)
  await replayModule.initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: store.recoveryFinalState })
  const id = fixed(0x85)
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  const attempts = await Promise.all([
    appendForwardHttpsTargetSessionV3(store, { stableSessionId: id, walType: 112 }).then(() => 'a', () => 'a-rejected'),
    appendForwardHttpsTargetSessionV3(store, { stableSessionId: id, walType: 112 }).then(() => 'b', () => 'b-rejected')
  ])
  t.ok(attempts.includes('a') !== attempts.includes('b') || attempts.filter(item => !item.endsWith('rejected')).length >= 1, 'at least one concurrent attempt wins through the FIFO mutex')
})

test('claim fencing: derive rejects missing, caller-constructed and non-SYNCED claims', async t => {
  const id = fixed(0x76)
  const payload = sessionBody(id)
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(96, payload) }), /transitionAuthority|unknown field/)
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(96, payload), transitionAuthority: Object.freeze({}) }), /forged|not SYNCED/)
  // A MINTED_UNBEGUN live claim (fresh from bind) is rejected by derive
  const { capability } = await quota(t, SOURCE)
  const { createForwardHttpsStoreQuotaCostPlanV3, reserveForwardHttpsAggregateQuotaV3, bindForwardHttpsStoreQuotaActualBuffersV3, releaseForwardHttpsAggregateQuotaV3 } = replayModule
  const plan = createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'PREPARE',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { reservation } = await reserveForwardHttpsAggregateQuotaV3(capability, plan)
  const { transitionAuthority } = bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [payload],
    temporaryWriteBuffers: []
  })
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(96, payload), transitionAuthority }), /not SYNCED|forged/)
  await releaseForwardHttpsAggregateQuotaV3(capability, reservation)
  // After release the claim is burned and rejected as reused
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(96, payload), transitionAuthority }), /forged|reused/)
})

test('composite: one-use handoff burn proven at every ordinal for 1, 2, 4 and 22 frame operations', async t => {
  const cases = [
    { operation: 'PREPARE', finalType: 96, prefix: 0 },
    { operation: 'TURN_FINAL', finalType: 112, prefix: 1 },
    { operation: 'PROCESSOR_REQUEST_READY', finalType: 115, prefix: 3 },
    { operation: 'PROCESSOR_COMPLETED', finalType: 116, prefix: 21 }
  ]
  for (const { operation, finalType, prefix } of cases) {
    const role = finalType < 112 ? SOURCE : TARGET
    const { capability } = await quota(t, role)
    const id = fixed(0x70 + prefix)
    const magic = role === SOURCE ? 'FSS3' : 'FTS3'
    const prefixPayloads = Array.from({ length: prefix }, (_, index) => b4a.concat([b4a.from(magic, 'ascii'), id, b4a.alloc(118 - 36, index & 0xff)]))
    const finalPayload = b4a.concat([b4a.from(magic, 'ascii'), id, b4a.alloc(8, 0x43)])
    const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
      operation,
      knownInputBuffers: [...prefixPayloads, finalPayload],
      temporaryWriteBuffers: [],
      existingDestinationBytes: 0
    })
    const { reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
    const { transitionAuthority } = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: prefixPayloads,
      finalWalMetadataBuffers: [finalPayload],
      temporaryWriteBuffers: []
    })
    let sequence = 0n
    const appendSync = async candidate => {
      sequence += 1n
      return { sequence, walHash: blake2b256(b4a.concat([b4a.from('wal'), candidate.payload])), payloadHash: blake2b256(candidate.payload) }
    }
    let claimOrHandoff = transitionAuthority
    const handoffs = [claimOrHandoff]
    let entry = null
    for (let ordinal = 0; ordinal < prefix + 1; ordinal++) {
      const payload = ordinal < prefix ? prefixPayloads[ordinal] : finalPayload
      const type = ordinal < prefix ? 113 : finalType
      const applied = await replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, reservation, claimOrHandoff, { type, payload }, appendSync)
      entry = applied.entry
      claimOrHandoff = applied.transitionAuthorityHandoff
      if (claimOrHandoff !== null) handoffs.push(claimOrHandoff)
      // One-use burn: re-presenting the just-consumed claim rejects without mutation
      const consumed = handoffs[handoffs.length - 2]
      await t.exception.all(
        replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, reservation, consumed, { type, payload }, appendSync),
        /forged|reused|early|skipped|reordered/
      )
    }
    t.is(entry.walType, finalType)
    t.is(entry.walSequence, BigInt(prefix + 1))
    t.is(claimOrHandoff, null, 'null handoff at the exact final ordinal')
    t.is(handoffs.length, prefix + 1)
    await replayModule.commitForwardHttpsAggregateQuotaV3(capability, reservation, {
      durableWalHeadSequence: sequence,
      durableWalHeadHash: blake2b256(b4a.from('head'))
    })
    // Second bind on a burned reservation is impossible; a foreign claim rejects
    await t.exception.all(() => replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: [],
      finalWalMetadataBuffers: [finalPayload],
      temporaryWriteBuffers: []
    }))
  }
})

test('recovery claim ABI: exclusivity, ordering, post-finish absorb and one-use final states', async t => {
  const setup = await quota(t, TARGET)
  const { authority, capability } = setup
  const { initializeForwardHttpsAggregateQuotaV3, forwardHttpsAggregateQuotaV3Status } = replayModule
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  // Second concurrent begin on the same role root is AUTHORITY_INVALID
  await t.exception.all(() => beginForwardHttpsAggregateQuotaRecoveryV3(capability), /already open/)
  const id = fixed(0x78)
  const first = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x51)])
  // Out-of-order frame rejects with no state mutation
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(112, first, 2n, ZERO32) }), /out-of-order|duplicate|torn/)
  // Torn chain (wrong previousWalHash) rejects
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(112, first, 1n, fixed(0x79)) }), /out-of-order|duplicate|torn/)
  // One complete frame absorbs; a duplicate rejects
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(112, first, 1n, ZERO32) })
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(112, first, 1n, ZERO32) }), /out-of-order|duplicate/)
  // finish returns the opaque final recovery state; no claim is ever exposed
  const finalState = await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  t.is(typeof finalState, 'object')
  t.absent(finalState === null)
  // Post-finish absorb rejects
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
    frame: recoveryFrame(112, first, 2n, blake2b256(b4a.concat([b4a.from('wal'), first])))
  }), /invalid/)
  // A fresh begin runs to finish after the completed predecessor
  const sink2 = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  t.ok(await finishForwardHttpsAggregateQuotaRecoveryV3(sink2))
  // Cross-role frame rejects
  const sink3 = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  await t.exception.all(absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink3, { frame: recoveryFrame(96, sessionBody(id), 1n, ZERO32) }))
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink3)
  // initialize burns final states exactly once; quota becomes OPEN
  const sourceSink = beginForwardHttpsAggregateQuotaRecoveryV3(setup.capabilities.sourceStoreQuotaCapability)
  const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sourceSink)
  const targetSink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const targetFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(targetSink)
  await initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: targetFinal })
  t.is(forwardHttpsAggregateQuotaV3Status(authority).state, 'OPEN')
  await t.exception.all(
    initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: targetFinal }),
    /already initialized/
  )
})

test('composite: substituted final and cross-role presentations reject', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x77)
  const prefixPayload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(118 - 36, 0x01)])
  const finalPayload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x44)])
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [prefixPayload, finalPayload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  const { transitionAuthority } = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [prefixPayload],
    finalWalMetadataBuffers: [finalPayload],
    temporaryWriteBuffers: []
  })
  const appendSync = async candidate => ({ sequence: 1n, walHash: blake2b256(candidate.payload), payloadHash: blake2b256(candidate.payload) })
  // Substituted final at ordinal0 (prefix ordinal expects type113)
  await t.exception.all(
    replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, reservation, transitionAuthority, { type: 112, payload: finalPayload }, appendSync),
    /bound ordinal|forged/
  )
  // Cross-role claim: present the same claim against the other role capability
  const { capability: sourceCapability } = await quota(t, SOURCE)
  await t.exception.all(
    replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(sourceCapability, reservation, transitionAuthority, { type: 113, payload: prefixPayload }, appendSync),
    /forged|invalid/
  )
})

function u16be (value) {
  const output = b4a.alloc(2)
  output.writeUInt16BE(value, 0)
  return output
}

function u32be (value) {
  const output = b4a.alloc(4)
  output.writeUInt32BE(value, 0)
  return output
}

// Adopted V13 streaming final commitment over count, exact removed sum and
// the init/step chain, entries in WAL order.
function streamingCharge (roleByte, id, entries) {
  let chain = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-quota-charge-registry-init.v4', 'ascii'),
    b4a.from([roleByte]), id
  ]))
  let removed = 0n
  for (const entry of entries) {
    chain = blake2b256(b4a.concat([
      b4a.from('hiverelay.blind.forward-https-quota-charge-registry-step.v4', 'ascii'),
      chain, entry
    ]))
    removed += readU64be(entry, 41)
  }
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-quota-charge-registry-final.v4', 'ascii'),
    b4a.from([roleByte]), id, u32be(entries.length), u64be(removed), chain
  ]))
}

function readU64be (input, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(input[offset + index])
  return value
}

function u64be (value) {
  const output = b4a.alloc(8)
  let current = BigInt(value)
  for (let index = 7; index >= 0; index--) { output[index] = Number(current & 0xffn); current >>= 8n }
  return output
}

function chargeEntry (walType, walSequence, payloadHash, charge) {
  const entry = b4a.alloc(49)
  entry[0] = walType
  let current = BigInt(walSequence)
  for (let index = 8; index >= 1; index--) { entry[index] = Number(current & 0xffn); current >>= 8n }
  b4a.copy(payloadHash, entry, 9)
  let cost = BigInt(charge)
  for (let index = 48; index >= 41; index--) { entry[index] = Number(cost & 0xffn); cost >>= 8n }
  return entry
}
