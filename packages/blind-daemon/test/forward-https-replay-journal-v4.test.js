import b4a from 'b4a'
import test from 'brittle'
import { blake2b256 } from '@hiverelay/blind-protocol'
import * as replayModule from '../forward-https-replay-journal-v4.js'
import {
  encodeForwardHttpsRetentionPrunedV3,
  decodeForwardHttpsRetentionPrunedV3,
  deriveForwardHttpsStoreWalQuotaEntryV3,
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

function sessionBody (id) {
  return b4a.concat([b4a.from('FSS3', 'ascii'), id, b4a.alloc(8, 0x41)])
}

test('export surface: exactly three additions and no registry export', async t => {
  const names = Object.keys(replayModule)
  t.ok(names.includes('encodeForwardHttpsRetentionPrunedV3'))
  t.ok(names.includes('decodeForwardHttpsRetentionPrunedV3'))
  t.ok(names.includes('deriveForwardHttpsStoreWalQuotaEntryV3'))
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
  t.is(b4a.toString(payload.subarray(0, 4), 'ascii'), 'FPR9')
  t.is(payload[4], 1)
  t.is(payload[5], 1)
  t.is(payload.readUInt32BE(72), 1)
  t.is(payload.readUInt32BE(80), 0)
  t.is(payload[84], 1)
  t.is(payload[85], 1)
  for (let index = 184; index < 256; index++) t.is(payload[index], 0)
  const decoded = decodeForwardHttpsRetentionPrunedV3(payload)
  t.is(decoded.role, 1)
  t.ok(b4a.equals(decoded.stableSessionId, id))
  t.is(decoded.priorSessionRevision, 3n)
  t.is(decoded.removedOrdinaryLogicalBytes, 808n)
  t.is(decoded.chargeEntryCount, 1)
  t.is(decoded.beforeAuthorityBitmap, 3)
  const expectedCharge = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-quota-charge-registry.v3', 'ascii'),
    b4a.from([1]), id, u32be(1), ...entries
  ]))
  t.ok(b4a.equals(decoded.chargeRegistryCommitment, expectedCharge))
  const expectedAuthority = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii'),
    b4a.from([1]), id, u64be(3n), u32be(3), ...Array.from({ length: 10 }, () => b4a.from(ZERO32))
  ]))
  t.ok(b4a.equals(decoded.authorityRegistryCommitment, expectedAuthority))
  const expectedState = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-prune-session-state.v3', 'ascii'),
    b4a.from([1]), id, u64be(3n), expectedCharge, expectedAuthority, b4a.from([1])
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
    reason: 'SEQUENCE_INVALID'
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
  const emptyCharge = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.forward-https-quota-charge-registry.v3', 'ascii'),
    b4a.from([2]), id, u32be(0)
  ]))
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

test('derive: ordinary SESSION frame charge is payload+frame', async t => {
  const id = fixed(0x66)
  const payload = sessionBody(id)
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(96, payload) })
  t.is(derived.role, SOURCE)
  t.is(derived.scope, 'SESSION')
  t.is(derived.walType, 96)
  t.is(derived.walSequence, 1n)
  t.is(derived.ordinaryLogicalCharge, payload.byteLength + payload.byteLength + 224)
  t.is(derived.terminalLogicalCharge, 0)
  t.is(derived.authorityBitmap, 0)
  t.ok(b4a.equals(derived.stableSessionId, id))
  t.is(derived.authorityCommitments.length, 10)
})

test('derive: type113 independent charge is exactly460', async t => {
  const id = fixed(0x67)
  const payload = b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(118 - 36, 0x42)])
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: TARGET, frame: frame(113, payload) })
  t.is(derived.ordinaryLogicalCharge, 460)
  t.is(derived.scope, 'SESSION')
  t.ok(b4a.equals(derived.stableSessionId, id))
})

test('derive: FTM9 minimal terminal yields bitmap640 and rederived class7/class9 commitments', async t => {
  const id = fixed(0x68)
  const expiresAtEpoch = 200000
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: TARGET,
    flags: 1,
    stableSessionId: id,
    sequence: 3n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 77,
    reason: 'SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x69),
    expiresAtEpoch,
    retainedUntilEpoch: expiresAtEpoch + 900
  })
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: TARGET, frame: frame(117, payload) })
  t.is(derived.ordinaryLogicalCharge, 0)
  t.is(derived.terminalLogicalCharge, 608)
  t.is(derived.authorityBitmap, 640)
  for (let index = 0; index < 10; index++) {
    if (index === 7 || index === 9) t.absent(b4a.equals(derived.authorityCommitments[index], ZERO32))
    else t.ok(b4a.equals(derived.authorityCommitments[index], ZERO32))
  }
})

test('derive: FPR9 prune transition has 736 role-global charge', async t => {
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
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(100, payload) })
  t.is(derived.scope, 'PRUNE_TRANSITION')
  t.is(derived.ordinaryLogicalCharge, 736)
  t.ok(b4a.equals(derived.stableSessionId, id))
})

test('derive: cross-role and unknown types are INTEGRITY', async t => {
  const id = fixed(0x6c)
  const payload = sessionBody(id)
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: TARGET, frame: frame(96, payload) }))
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(55, payload) }))
  await t.exception.all(() => deriveForwardHttpsStoreWalQuotaEntryV3({ role: SOURCE, frame: frame(112, payload) }))
})

function u32be (value) {
  const output = b4a.alloc(4)
  output.writeUInt32BE(value, 0)
  return output
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
