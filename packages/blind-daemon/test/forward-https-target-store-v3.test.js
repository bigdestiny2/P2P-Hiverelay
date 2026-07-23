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
  closeForwardHttpsAggregateQuotaV3
} from '../forward-https-replay-journal-v4.js'
import {
  openForwardHttpsTargetStoreV3,
  openForwardHttpsTargetSessionV3,
  appendForwardHttpsTargetSessionV3,
  terminalizeForwardHttpsTargetSessionV3,
  terminalizeForwardHttpsTargetAbsentSequenceV3,
  pruneForwardHttpsTargetSessionV3,
  forwardHttpsTargetStoreV3Status,
  closeForwardHttpsTargetStoreV3
} from '../forward-https-target-store-v3.js'

const execFileAsync = promisify(execFile)

function fixed (byte) {
  return b4a.alloc(32, byte)
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
  // A type113 crypto reservation is an independent removable charge entry
  const reserved = await appendForwardHttpsTargetSessionV3(store, {
    stableSessionId: id,
    walType: 113,
    body: b4a.alloc(118 - 36, 0x52),
    plannedRemovableChargeEntryCount: 1
  })
  t.is(reserved.payload.byteLength, 118)
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.registry.count, 2)
  const status = forwardHttpsTargetStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const recoveredSlot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.registry.count, 2)
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
