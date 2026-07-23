import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import test from 'brittle'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'
import {
  openForwardHttpsAggregateQuotaV3,
  mintForwardHttpsAggregateQuotaCapabilitiesV3,
  closeForwardHttpsAggregateQuotaV3,
  beginForwardHttpsAggregateQuotaRecoveryV3,
  finishForwardHttpsAggregateQuotaRecoveryV3,
  initializeForwardHttpsAggregateQuotaV3,
  assertForwardHttpsAggregateQuotaOperationalV3,
  failForwardHttpsAggregateQuotaWalAttemptV3,
  forwardHttpsAggregateQuotaV3Status
} from '../forward-https-replay-journal-v4.js'
import {
  openForwardHttpsTargetStoreV3,
  openForwardHttpsTargetSessionV3,
  appendForwardHttpsTargetSessionV3,
  terminalizeForwardHttpsTargetSessionV3,
  terminalizeForwardHttpsTargetAbsentSequenceV3,
  pruneForwardHttpsTargetSessionV3,
  forwardHttpsTargetStoreV3Status,
  closeForwardHttpsTargetStoreV3,
  FORWARD_HTTPS_TARGET_STORE_V3_HISTORIC_IDENTITY
} from '../forward-https-target-store-v3.js'
import {
  FORWARD_HTTPS_STORAGE_SLOT_STATE_V3,
  classifyForwardHttpsHistoricIdentityV3
} from '../forward-https-storage-authority-v3.js'

const execFileAsync = promisify(execFile)

function fixed (byte) {
  return b4a.alloc(32, byte)
}

const SLOT = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3
const IDENTITY = FORWARD_HTTPS_TARGET_STORE_V3_HISTORIC_IDENTITY

function identityOf (slot) {
  return classifyForwardHttpsHistoricIdentityV3(slot.state, slot.prunedReleased)
}

function prefixPayload (id, fill = 0x52) {
  return b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(118 - 36, fill)])
}

// Raw durable WAL append outside any quota operation, used to construct
// crashed-prefix evidence; recovery replays it exactly once on reopen.
async function rawAppend (store, type, payload) {
  return store.store.appendAndApply({ type, transactionId: b4a.alloc(32, 0x66), virtualBucket: 0, payload }, () => {})
}

async function roots (t) {
  const base = await createBlindBoundaryScratch('fhts3-')
  t.teardown(async () => {
    await removeBlindBoundaryScratch(base)
  })
  const names = ['source-replay', 'target-replay', 'source-store', 'target-store']
  const out = {}
  for (const name of names) {
    out[name] = path.join(base, name)
    await fs.mkdir(out[name], { mode: 0o700 })
    await fs.chmod(out[name], 0o700)
  }
  return out
}

async function quota (t, r) {
  const authority = await openForwardHttpsAggregateQuotaV3({
    sourceReplayRoot: r['source-replay'],
    targetReplayRoot: r['target-replay'],
    sourceStoreRoot: r['source-store'],
    targetStoreRoot: r['target-store'],
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184,
    monotonicMillis: () => Date.now(),
    callbackTimeoutMillis: 15000,
    faultInjector: null
  })
  t.teardown(async () => {
    await closeForwardHttpsAggregateQuotaV3(authority).catch(() => {})
  })
  return mintForwardHttpsAggregateQuotaCapabilitiesV3(authority)
}

function storeOptions (r, capabilities, overrides = {}) {
  return {
    root: r['target-store'],
    storeQuotaCapability: capabilities.targetStoreQuotaCapability,
    storeId: fixed(0x41),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x42),
    durabilityContinuityHash: fixed(0x43),
    monotonicMillis: () => Date.now(),
    ...overrides
  }
}

test('target store: fresh OPEN TURN_FINAL allocates and type113 counts independently', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x51)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  const opened = await openForwardHttpsTargetSessionV3(store, { stableSessionId: id, body: b4a.alloc(8, 0x51) })
  t.is(opened.walSequence, 1n)
  // A type113 crypto reservation is the prefix frame of a two-frame
  // TURN_FINAL operation: 113 then the 112 final, both removable entries
  const reserved = await appendForwardHttpsTargetSessionV3(store, {
    stableSessionId: id,
    walType: 113,
    body: b4a.alloc(118 - 36, 0x52),
    plannedRemovableChargeEntryCount: 2
  })
  t.is(reserved.payload.byteLength, 118)
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.registry.count, 3)
  const status = forwardHttpsTargetStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const recoveredSlot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.registry.count, 3)
})

test('target store: minimal absent-sequence terminal and terminal-only prune', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x52)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  const result = await terminalizeForwardHttpsTargetAbsentSequenceV3(store, {
    stableSessionId: id,
    sequence: 4n,
    exactRequestCommitment: fixed(0x53),
    expiresAtEpoch: 2000,
    newTrustedEpochHighWatermark: 1500
  })
  t.is(result.payload[5], 2) // TARGET role byte
  t.is(result.payload.readUInt16BE(6), 1)
  const status = forwardHttpsTargetStoreV3Status(store)
  t.is(status.consumedUnprunedSlots, 1)
  const pruned = await pruneForwardHttpsTargetSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 2901 })
  t.is(pruned.payload.readUInt32BE(72), 0)
  t.is(pruned.payload.readUInt32BE(76), 640)
  t.is(pruned.payload[85], 2)
  const after = forwardHttpsTargetStoreV3Status(store)
  t.is(after.consumedPrunedSlots, 1)
})

test('target store: existing-session terminalization and budget reason', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x54)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  const terminal = await terminalizeForwardHttpsTargetSessionV3(store, {
    stableSessionId: id,
    sequence: 9n,
    reason: 'BUDGET_EXHAUSTED',
    newTrustedEpochHighWatermark: 5
  })
  t.is(terminal.payload.byteLength, 192)
  t.is(b4a.toString(terminal.payload.subarray(77, 77 + 16), 'ascii'), 'BUDGET_EXHAUSTED')
  await t.exception.all(openForwardHttpsTargetSessionV3(store, { stableSessionId: id }), /not NEVER_SEEN/)
})

test('target store: cross-role frame recovery is INTEGRITY', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x55)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  // A source WAL type can never be appended through the target store
  await t.exception.all(appendForwardHttpsTargetSessionV3(store, { stableSessionId: id, walType: 96 }), /not an ordinary target/)
})

test('prefix partition: FRESH type113 prefix claims exactly one PREFIX_ALLOCATED slot', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x56)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await rawAppend(store, 113, prefixPayload(id))
  await rawAppend(store, 113, prefixPayload(id, 0x53))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.state, SLOT.PREFIX_ALLOCATED)
  t.is(identityOf(slot), IDENTITY.PRESENT_PREFIX_ALLOCATED)
  t.is(slot.registry.count, 2)
  t.is(slot.orphan.entries.length, 2)
  t.is(slot.orphan.removedSum, 920n)
  t.is(slot.orphan.lastRevision, 2n)
  const status = forwardHttpsTargetStoreV3Status(reopened)
  t.is(status.unconsumedSlots, status.slotCapacity - 1, 'exactly one slot claimed')
})

test('prefix partition: EXISTING-session type113 prefix overlays ALLOCATED_WITH_PREFIX with complete preservation', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x57)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id, body: b4a.alloc(8, 0x51) })
  const before = store.slots.get(b4a.toString(id, 'hex'))
  t.is(before.registry.count, 1)
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.state, SLOT.ALLOCATED_WITH_PREFIX)
  t.is(identityOf(slot), IDENTITY.ALLOCATED_WITH_PREFIX)
  t.is(slot.registry.count, 2, 'pre-operation entry preserved plus the orphan entry')
  t.is(slot.orphan.entries.length, 1)
  t.is(slot.orphan.removedSum, 460n)
  t.is(slot.orphan.lastRevision, 2n)
  const status = forwardHttpsTargetStoreV3Status(reopened)
  t.is(status.unconsumedSlots, status.slotCapacity - 1, 'no second slot is claimed')
})

test('prefix partition: matching final applies exactly once for both classes', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const freshId = fixed(0x58)
  const existingId = fixed(0x59)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  // FRESH prefix completed by its matching final
  await rawAppend(store, 113, prefixPayload(freshId))
  await rawAppend(store, 112, b4a.concat([b4a.from('FTS3', 'ascii'), freshId, b4a.alloc(8, 0x54)]))
  // EXISTING prefix completed by its matching final
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: existingId })
  await rawAppend(store, 113, prefixPayload(existingId))
  await rawAppend(store, 114, b4a.concat([b4a.from('FTS3', 'ascii'), existingId, b4a.alloc(8, 0x55)]))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const fresh = reopened.slots.get(b4a.toString(freshId, 'hex'))
  t.is(fresh.state, SLOT.ALLOCATED)
  t.is(identityOf(fresh), IDENTITY.PRESENT_ALLOCATED)
  t.is(fresh.orphan, null)
  t.is(fresh.registry.count, 2)
  const existing = reopened.slots.get(b4a.toString(existingId, 'hex'))
  t.is(existing.state, SLOT.ALLOCATED)
  t.is(identityOf(existing), IDENTITY.PRESENT_ALLOCATED)
  t.is(existing.orphan, null)
  t.is(existing.registry.count, 3)
  const status = forwardHttpsTargetStoreV3Status(reopened)
  t.is(status.unconsumedSlots, status.slotCapacity - 2)
})

test('per-step identity goldens: latest slot-disposing transition governs', async t => {
  const r = await roots(t)
  const capabilities = await quota(t, r)
  const id = fixed(0x5a)
  // OPEN + target112 assigns PRESENT_ALLOCATED
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  t.is(identityOf(store.slots.get(b4a.toString(id, 'hex'))), IDENTITY.PRESENT_ALLOCATED)
  // +k complete target113 (no final, no abort) assigns ALLOCATED_WITH_PREFIX
  await rawAppend(store, 113, prefixPayload(id))
  await rawAppend(store, 113, prefixPayload(id, 0x5b))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(identityOf(slot), IDENTITY.ALLOCATED_WITH_PREFIX)
  t.is(slot.orphan.entries.length, 2)
  t.is(slot.orphan.removedSum, 920n)
})

test('quota gate: OPEN admits, fail-WAL enters FAILED_WAL_OUTCOME_UNKNOWN_PENDING and blocks all work', async t => {
  const r = await roots(t)
  const authority = await openForwardHttpsAggregateQuotaV3({
    sourceReplayRoot: r['source-replay'],
    targetReplayRoot: r['target-replay'],
    sourceStoreRoot: r['source-store'],
    targetStoreRoot: r['target-store'],
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184,
    monotonicMillis: () => Date.now(),
    callbackTimeoutMillis: 15000,
    faultInjector: null
  })
  t.teardown(async () => { await closeForwardHttpsAggregateQuotaV3(authority).catch(() => {}) })
  const caps = mintForwardHttpsAggregateQuotaCapabilitiesV3(authority)
  // Gate before initialize: quota is not yet OPEN
  await t.exception.all(() => assertForwardHttpsAggregateQuotaOperationalV3(caps.targetStoreQuotaCapability), /not operational/)
  // Initialize from empty role roots through the recovery claim ABI: claims
  // are sink-private; finish returns the final recovery state.
  const sourceSink = beginForwardHttpsAggregateQuotaRecoveryV3(caps.sourceStoreQuotaCapability)
  const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sourceSink)
  const targetSink = beginForwardHttpsAggregateQuotaRecoveryV3(caps.targetStoreQuotaCapability)
  const targetFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(targetSink)
  await initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: targetFinal })
  // OPEN and localOperational: the gate succeeds without mutation
  t.is(assertForwardHttpsAggregateQuotaOperationalV3(caps.targetStoreQuotaCapability), undefined)
  t.is(forwardHttpsAggregateQuotaV3Status(authority).state, 'OPEN')
  // fail-WAL: absorbing FAILED_WAL_OUTCOME_UNKNOWN_PENDING; gate and later work reject
  failForwardHttpsAggregateQuotaWalAttemptV3(caps.targetStoreQuotaCapability)
  const failed = forwardHttpsAggregateQuotaV3Status(authority)
  t.is(failed.state, 'FAILED_WAL_OUTCOME_UNKNOWN_PENDING')
  t.absent(failed.localOperational)
  t.is(failed.blocker, 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_INTEGRITY')
  await t.exception.all(() => assertForwardHttpsAggregateQuotaOperationalV3(caps.targetStoreQuotaCapability), /not operational/)
})

test('target store: kill after complete tombstone recovers applied exactly once', async t => {
  const base = await createBlindBoundaryScratch('fhkill-test-')
  t.teardown(async () => { await removeBlindBoundaryScratch(base) })
  for (const name of ['source-replay', 'target-replay', 'source-store', 'target-store']) {
    await fs.mkdir(path.join(base, name), { mode: 0o700 })
    await fs.chmod(path.join(base, name), 0o700)
  }
  const fixture = new URL('./forward-https-storage-kill-fixture.mjs', import.meta.url)
  const fixturePath = fileURLToPath(fixture)
  const setup = await execFileAsync(process.execPath, [fixturePath, 'setup', base])
  t.is(JSON.parse(setup.stdout).walSequence, '1')
  await t.exception.all(execFileAsync(process.execPath, [fixturePath, 'crash', base]))
  const verify = await execFileAsync(process.execPath, [fixturePath, 'verify', base])
  const recovered = JSON.parse(verify.stdout)
  t.is(recovered.state, 'OPEN')
  t.is(recovered.walHeadSequence, '2')
  t.is(recovered.slotState, 'FREE')
  t.ok(recovered.prunedReleased)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity)
})
