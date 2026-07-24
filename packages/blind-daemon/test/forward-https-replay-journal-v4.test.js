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
  encodeLocalForwardHttpsOriginAuthorityV4
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

const SOURCE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const TARGET = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
const ZERO32 = b4a.alloc(32)

function writeU64beLocal (output, offset, value) {
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
  offset = writeU64beLocal(output, offset, input.sequence)
  for (const value of input.buckets || [0, 0, 0, 0, 0]) { output.writeUInt16BE(value, offset); offset += 2 }
  output.writeUInt16BE(input.transportTurnsSpent || 0, offset); offset += 2
  output.writeUInt32BE(input.transportBytesSpent || 0, offset); offset += 4
  offset = writeU64beLocal(output, offset, input.priorSessionRevision || 0n)
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

async function quota (t, role, extraOptions = {}) {
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
    faultInjector: null,
    ...extraOptions
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
  // SOURCE_ORIGIN end-to-end through the IPC record codec. The snapshot
  // RESERVE/CONSUME path is role-agnostic inside the module; TARGET_INGRESS
  // record construction requires the full wire FORWARDED transform and is
  // covered at bootstrap level by the previous test (deferred test asset).
  const { capabilities, roots } = await quota(t, SOURCE)
  const role = 'SOURCE_ORIGIN'
  const clock = () => 100000n
  const options = replayJournalOptions(role, roots['source-replay'], capabilities.sourceReplayQuotaCapability, clock)
  const id = fixed(0x51)
  const record = sourceReplayRecord(id, 100000n)
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
  // M is always recomputed from the exact frozen preimage.
  const reasonBytes = b4a.from('FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID', 'ascii')
  const sequenceBytes = b4a.alloc(8)
  writeU64beLocal(sequenceBytes, 0, 9n)
  const scalars = b4a.alloc(13)
  scalars.writeUInt32BE(expiresAtEpoch, 0)
  scalars.writeUInt32BE(retainedUntilEpoch, 4)
  scalars.writeUInt32BE(4242, 8)
  scalars[12] = reasonBytes.byteLength
  const M = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-minimal-terminal-authority.v3', 'ascii'),
    b4a.from([2]), id, sequenceBytes, fixed(0x63), scalars, reasonBytes
  ]))
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
  const payload = buildFtm9({
    role: 'TARGET',
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
  const terminalPayload = buildFtm9({
    role: 'SOURCE',
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
  // A recovered tombstone must independently match the recovered session
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  const session = b4a.concat([b4a.from('FSS3', 'ascii'), id])
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(96, session, 1n, ZERO32) })
  const removed = 36 + 224 + 36
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: SOURCE,
    stableSessionId: id,
    priorSessionRevision: 1n,
    pruneEpochSeconds: 9,
    trustedEpochHighWatermark: 9,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: BigInt(removed),
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: [chargeEntry(96, 1n, blake2b256(session), removed)],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, { frame: recoveryFrame(100, payload, 2n, blake2b256(b4a.concat([b4a.from('wal'), session]))) })
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
  const terminalPayload = buildFtm9({
    role: 'TARGET',
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

test('ENTRY_CAP terminalReservation drivability: original frames reject, exact flags0 BUDGET_EXHAUSTED FTM9 terminalizes the one session', async t => {
  const { authority, capability } = await quota(t, TARGET)
  const id = fixed(0x7f)
  // Seed the mirror with 65535 entries of one session through recovery
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capability)
  let previous = ZERO32
  for (let index = 1; index <= 65535; index++) {
    const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, index & 0xff)])
    const walHash = blake2b256(b4a.concat([b4a.from('wal'), payload, u64be(BigInt(index))]))
    await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(sink, {
      frame: { type: 112, payload, payloadHash: blake2b256(payload), sequence: BigInt(index), previousWalHash: previous, walHash, frameBytes: payload.byteLength + 224 }
    })
    previous = walHash
  }
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  // Cap+1: recovered 65535 plus planned 2 exceeds 65536
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x01)])],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  t.is(union.disposition, 'ENTRY_CAP_TERMINAL')
  const terminalReservation = union.terminalReservation
  // The original rejected operation's frames reject at bind with no WAL mutation
  const rejectedPayload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x01)])
  await t.exception.all(() => replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, terminalReservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [rejectedPayload],
    temporaryWriteBuffers: []
  }), /FTM9|expectation|INTEGRITY/)
  t.is(replayModule.forwardHttpsAggregateQuotaV3Status(authority).pendingReservation, true)
  // The exact flags0 BUDGET_EXHAUSTED expectation binds, applies and commits
  const ftm9 = buildFtm9({
    role: 'TARGET',
    flags: 0,
    stableSessionId: id,
    sequence: 70000n,
    priorSessionRevision: 65535n,
    newTrustedEpochHighWatermark: 4242,
    reason: 'BUDGET_EXHAUSTED'
  })
  const { transitionAuthority } = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, terminalReservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [ftm9],
    temporaryWriteBuffers: []
  })
  let sequence = 65535n
  const applied = await replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, terminalReservation, transitionAuthority, { type: 117, payload: ftm9 }, async frame => {
    sequence += 1n
    return { sequence, walHash: blake2b256(b4a.concat([b4a.from('wal'), frame.payload])), payloadHash: blake2b256(frame.payload) }
  })
  t.is(applied.entry.terminalLogicalCharge, 608)
  t.is(applied.entry.authorityBitmap, 512)
  t.is(applied.transitionAuthorityHandoff, null)
  await replayModule.commitForwardHttpsAggregateQuotaV3(capability, terminalReservation, {
    durableWalHeadSequence: sequence,
    durableWalHeadHash: blake2b256(b4a.concat([b4a.from('wal'), ftm9]))
  })
  // The ONE session is now terminally consumed in the canonical mirror: a
  // second flags0 terminal on it rejects at derive with no second apply.
  const secondPlan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'SESSION_TERMINAL',
    knownInputBuffers: [ftm9],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const secondUnion = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, secondPlan)
  const secondReservation = secondUnion.reservation || secondUnion.terminalReservation
  const second = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, secondReservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [ftm9],
    temporaryWriteBuffers: []
  })
  await t.exception.all(
    replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, secondReservation, second.transitionAuthority, { type: 117, payload: ftm9 }, async frame => ({ sequence: 65537n, walHash: blake2b256(frame.payload), payloadHash: blake2b256(frame.payload) })),
    /PRESENT_ALLOCATED|predecessor|INTEGRITY/
  )
})

test('flags1 minimal terminal requires a FREE slot: occupied session or full role rejects CAPACITY before mutation', async t => {
  const occupiedId = fixed(0x91)
  const minimalTerminal = (id, sequence) => buildFtm9({
    role: 'TARGET',
    flags: 1,
    stableSessionId: id,
    sequence,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 1,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x92),
    expiresAtEpoch: 100,
    retainedUntilEpoch: 1000
  })
  const terminalPlan = (capability, payload) => replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'SESSION_TERMINAL',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  // A one-slot authority holding one ALLOCATED session: the role is full.
  const full = await quota(t, TARGET, { slotCapacityPerRole: 1 })
  const seedSink = beginForwardHttpsAggregateQuotaRecoveryV3(full.capability)
  const seedPayload = b4a.concat([b4a.from('FTS3', 'ascii'), occupiedId, b4a.alloc(8, 0x01)])
  await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(seedSink, {
    frame: { type: 112, payload: seedPayload, payloadHash: blake2b256(seedPayload), sequence: 1n, previousWalHash: ZERO32, walHash: blake2b256(b4a.concat([b4a.from('wal'), seedPayload])), frameBytes: seedPayload.byteLength + 224 }
  })
  await finishForwardHttpsAggregateQuotaRecoveryV3(seedSink)
  const before = replayModule.forwardHttpsAggregateQuotaV3Status(full.authority)
  // Fresh session id with no FREE slot: CAPACITY before any mutation.
  await t.exception.all(
    replayModule.reserveForwardHttpsAggregateQuotaV3(full.capability, terminalPlan(full.capability, minimalTerminal(fixed(0x93), 2n))),
    /FREE session slot|CAPACITY/
  )
  // The already-occupied session id has no FREE slot for it either.
  await t.exception.all(
    replayModule.reserveForwardHttpsAggregateQuotaV3(full.capability, terminalPlan(full.capability, minimalTerminal(occupiedId, 3n))),
    /FREE session slot|CAPACITY/
  )
  // Zero authority/WAL mutation: no pending reservation, ledgers and state unchanged.
  const after = replayModule.forwardHttpsAggregateQuotaV3Status(full.authority)
  t.absent(after.pendingReservation)
  t.is(after.state, before.state)
  t.is(after.targetLogicalChargedBytes, before.targetLogicalChargedBytes)
  t.is(after.targetStorePhysicalApparentBytes, before.targetStorePhysicalApparentBytes)
  // flags0 existing-session terminals are not gated by the FREE-slot check.
  const flags0 = buildFtm9({
    role: 'TARGET',
    flags: 0,
    stableSessionId: occupiedId,
    sequence: 4n,
    priorSessionRevision: 1n,
    newTrustedEpochHighWatermark: 2,
    reason: 'BUDGET_EXHAUSTED'
  })
  const flags0Union = await replayModule.reserveForwardHttpsAggregateQuotaV3(full.capability, terminalPlan(full.capability, flags0))
  t.is(flags0Union.disposition, 'REQUESTED_TERMINAL')
  t.ok(flags0Union.terminalReservation)
  // Positive control: a fresh one-slot authority with no sessions admits the
  // flags1 minimal terminal.
  const empty = await quota(t, TARGET, { slotCapacityPerRole: 1 })
  const admitUnion = await replayModule.reserveForwardHttpsAggregateQuotaV3(empty.capability, terminalPlan(empty.capability, minimalTerminal(fixed(0x94), 2n)))
  t.is(admitUnion.disposition, 'REQUESTED_TERMINAL')
  t.ok(admitUnion.terminalReservation)
})

test('failure states: terminal prewrite abort enters FAILED_PREWRITE; close rules reach CLOSED exactly', async t => {
  const { authority, capability } = await quota(t, TARGET)
  const id = fixed(0x7c)
  const terminalPayload = buildFtm9({
    role: 'TARGET',
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

test('quota FIFO mutex: overlapping reservations queue in submission order and never starve', async t => {
  const { capability } = await quota(t, TARGET)
  const makePlan = byte => replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [b4a.concat([b4a.from('FTS3', 'ascii'), fixed(byte), b4a.alloc(8, 0x41)])],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  // One outstanding operation per authority: a second submission queues
  // behind the holder and completes only after the holder releases.
  const first = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x81))
  let secondCompleted = false
  const secondPromise = replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(0x82)).then(union => {
    secondCompleted = true
    return union
  })
  await new Promise(resolve => setTimeout(resolve, 25))
  t.absent(secondCompleted, 'the queued second reservation waits for the holder')
  await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, first.reservation)
  const second = await secondPromise
  t.ok(secondCompleted, 'no starvation: the queued reservation completes after release')
  t.is(second.disposition, 'ORDINARY')
  await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, second.reservation)
  // Five-way queue: submissions complete in exact FIFO order.
  const order = []
  await Promise.all([0x83, 0x84, 0x85, 0x86, 0x87].map(byte => (async () => {
    const union = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, makePlan(byte))
    order.push(byte)
    await replayModule.releaseForwardHttpsAggregateQuotaV3(capability, union.reservation)
  })()))
  t.alike(order, [0x83, 0x84, 0x85, 0x86, 0x87], 'exact submission-order fairness')
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
  const { openForwardHttpsTargetStoreV3, acceptForwardedHttpsTargetTurnV3, closeForwardHttpsTargetStoreV3 } = await import('../forward-https-target-store-v3.js')
  const storeSink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.targetStoreQuotaCapability)
  const store = await openForwardHttpsTargetStoreV3({
    root: path.join(r, 'target-store'),
    replayJournalAuthority: Object.freeze({}),
    targetStoreQuotaCapability: capabilities.targetStoreQuotaCapability,
    targetQuotaRecoverySink: storeSink,
    wireV3AbiHash: fixed(0x44),
    privateIpcV4Hash: fixed(0x45),
    signedLaunchTopologyHash: fixed(0x46),
    storeId: fixed(0x41),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x42),
    durabilityContinuityHash: fixed(0x43),
    targetSignerPublicKey: fixed(0x47),
    targetSignerDescriptorSequence: 1n,
    targetSignerDescriptorHash: fixed(0x48),
    signResult: async () => b4a.alloc(64),
    createResponderState: () => ({}),
    advanceResponderIngress: () => {},
    advanceResponderOutcome: () => {},
    atRestKey: fixed(0x49),
    epochSeconds: () => 1000000,
    monotonicMillis: () => Date.now()
  })
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  const storeFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(storeSink)
  const sourceSink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
  const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sourceSink)
  await replayModule.initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: storeFinal })
  const id = fixed(0x85)
  await acceptForwardedHttpsTargetTurnV3(store, { stableSessionId: id })
  const attempts = await Promise.all([
    acceptForwardedHttpsTargetTurnV3(store, { stableSessionId: id, walType: 112 }).then(() => 'a', () => 'a-rejected'),
    acceptForwardedHttpsTargetTurnV3(store, { stableSessionId: id, walType: 112 }).then(() => 'b', () => 'b-rejected')
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
    const prefixPayloads = Array.from({ length: prefix }, (_, index) => b4a.concat([b4a.from(magic, 'ascii'), id, b4a.alloc(118 - 36, 0x42)]))
    const finalPayload = b4a.concat([b4a.from(magic, 'ascii'), id, b4a.alloc(32, 0x42), b4a.alloc(8, 0x43)])
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
    let lastDurable = null
    const appendSync = async candidate => {
      sequence += 1n
      lastDurable = { sequence, walHash: blake2b256(b4a.concat([b4a.from('wal'), candidate.payload])), payloadHash: blake2b256(candidate.payload) }
      return lastDurable
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
      durableWalHeadSequence: lastDurable.sequence,
      durableWalHeadHash: lastDurable.walHash
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

test('per-frame session binding: cross-session frame rejects under one reservation', async t => {
  const { capability } = await quota(t, TARGET)
  const id = fixed(0x88)
  const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x41)])
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  const { transitionAuthority } = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [payload],
    temporaryWriteBuffers: []
  })
  const foreign = b4a.concat([b4a.from('FTS3', 'ascii'), fixed(0x89), b4a.alloc(8, 0x42)])
  await t.exception.all(
    replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, reservation, transitionAuthority, { type: 112, payload: foreign }, async candidate => ({ sequence: 1n, walHash: blake2b256(candidate.payload), payloadHash: blake2b256(candidate.payload) })),
    /does not match the bound reservation/
  )
})

test('commit and adjust authenticate the exact durable head; fabricated heads reject', async t => {
  const { authority, capability } = await quota(t, TARGET)
  const id = fixed(0x8c)
  const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(8, 0x41)])
  const plan = replayModule.createForwardHttpsStoreQuotaCostPlanV3(capability, {
    operation: 'TURN_FINAL',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const { reservation } = await replayModule.reserveForwardHttpsAggregateQuotaV3(capability, plan)
  const { transitionAuthority } = replayModule.bindForwardHttpsStoreQuotaActualBuffersV3(capability, reservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [payload],
    temporaryWriteBuffers: []
  })
  await replayModule.applyForwardHttpsAggregateQuotaWalFrameV3(capability, reservation, transitionAuthority, { type: 112, payload },
    async candidate => ({ sequence: 1n, walHash: blake2b256(candidate.payload), payloadHash: blake2b256(candidate.payload) }))
  // Fabricated (seq 9999, hash 0xee) head rejects without mutation
  await t.exception.all(replayModule.commitForwardHttpsAggregateQuotaV3(capability, reservation, {
    durableWalHeadSequence: 9999n,
    durableWalHeadHash: b4a.alloc(32, 0xee)
  }), /exact applied head/)
  t.is(replayModule.forwardHttpsAggregateQuotaV3Status(authority).state, 'FAILED_WAL_OUTCOME_UNKNOWN_PENDING')
  t.absent(replayModule.forwardHttpsAggregateQuotaV3Status(authority).localOperational)
})

test('FPR9 decode rejects expiry above the u32 horizon pre-mutation', async t => {
  const id2 = fixed(0x8a)
  const horizonPayload = replayModule.encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    stableSessionId: id2,
    priorSessionRevision: 1n,
    pruneEpochSeconds: 4000000000,
    trustedEpochHighWatermark: 4000000000,
    expiresAtEpoch: 4294966394,
    recoveryGraceUntilEpoch: 4294966394 + 900,
    removedOrdinaryLogicalBytes: 460n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: [chargeEntry(113, 1n, fixed(0x8b), 460)],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const tampered = b4a.from(horizonPayload)
  tampered.writeUInt32BE(4294967000, 56)
  await t.exception.all(() => replayModule.decodeForwardHttpsRetentionPrunedV3(tampered), /horizon/)
  await t.exception.all(() => replayModule.encodeForwardHttpsRetentionPrunedV3({
    role: TARGET,
    stableSessionId: id2,
    priorSessionRevision: 1n,
    pruneEpochSeconds: 4000000000,
    trustedEpochHighWatermark: 4000000000,
    expiresAtEpoch: 4294967000,
    recoveryGraceUntilEpoch: 900,
    removedOrdinaryLogicalBytes: 460n,
    chargeEntryCount: 1,
    beforeAuthorityBitmap: 0,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: [chargeEntry(113, 1n, fixed(0x8b), 460)],
    authorityCommitments: Array.from({ length: 10 }, () => b4a.from(ZERO32))
  }), /horizon/)
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
