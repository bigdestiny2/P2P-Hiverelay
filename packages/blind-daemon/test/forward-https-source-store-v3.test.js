import fs from 'node:fs/promises'
import path from 'node:path'
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
  initializeForwardHttpsAggregateQuotaV3
} from '../forward-https-replay-journal-v4.js'
import {
  openForwardHttpsSourceStoreV3,
  prepareForwardHttpsSourceSessionV3,
  appendForwardHttpsSourceSessionV3,
  terminalizeForwardHttpsSourceSessionV3,
  terminalizeForwardHttpsSourceAbsentSequenceV3,
  pruneForwardHttpsSourceSessionV3,
  forwardHttpsSourceStoreV3Status,
  closeForwardHttpsSourceStoreV3,
  FORWARD_HTTPS_SOURCE_STORE_V3_WAL_TYPE
} from '../forward-https-source-store-v3.js'

function fixed (byte) {
  return b4a.alloc(32, byte)
}

async function roots (t) {
  const base = await createBlindBoundaryScratch('fhss3-')
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

async function quota (t, r, faultInjector = null) {
  const authority = await openForwardHttpsAggregateQuotaV3({
    sourceReplayRoot: r['source-replay'],
    targetReplayRoot: r['target-replay'],
    sourceStoreRoot: r['source-store'],
    targetStoreRoot: r['target-store'],
    maximumDurableBytesPerStore: 8589934592,
    maximumForwardStorageBytesAggregate: 17179869184,
    monotonicMillis: () => Date.now(),
    callbackTimeoutMillis: 15000,
    faultInjector
  })
  t.teardown(async () => {
    await closeForwardHttpsAggregateQuotaV3(authority).catch(() => {})
  })
  return { authority, capabilities: mintForwardHttpsAggregateQuotaCapabilitiesV3(authority) }
}

// Every store operation passes the operational gate, so the quota authority
// must be OPEN: after the first store recovery completes, finish the other
// role's recovery and initialize exactly once per authority.
const initializedAuthorities = new Set()
async function openStore (authority, r, capabilities, overrides) {
  const store = await openForwardHttpsSourceStoreV3(storeOptions(r, capabilities, overrides))
  if (!initializedAuthorities.has(authority)) {
    initializedAuthorities.add(authority)
    const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.targetStoreQuotaCapability)
    const targetFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
    await initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: store.recoveryFinalState, targetRecoveryFinalState: targetFinal })
  }
  return store
}

function storeOptions (r, capabilities, overrides = {}) {
  return {
    root: r['source-store'],
    storeQuotaCapability: capabilities.sourceStoreQuotaCapability,
    storeId: fixed(0x21),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x22),
    durabilityContinuityHash: fixed(0x23),
    monotonicMillis: () => Date.now(),
    ...overrides
  }
}

test('source store: fresh PREPARED_NEW allocates one slot and recovers', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x31)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  const prepared = await prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id, body: b4a.alloc(16, 0x41) })
  t.is(prepared.walSequence, 1n)
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
  await appendForwardHttpsSourceSessionV3(store, { stableSessionId: id, walType: FORWARD_HTTPS_SOURCE_STORE_V3_WAL_TYPE.TRANSPORT_RESERVED, body: b4a.alloc(4, 0x42) })
  await closeForwardHttpsSourceStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(reopened)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity - 1)
  t.is(recovered.walHeadSequence, 2n)
})

test('source store: duplicate fresh identity rejects; slot identity ignores sequence', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x32)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id })
  await t.exception.all(prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id }), /not NEVER_SEEN/)
  // Later sequences reuse the same ALLOCATED slot: no additional slot is consumed
  await appendForwardHttpsSourceSessionV3(store, { stableSessionId: id, walType: 97 })
  await appendForwardHttpsSourceSessionV3(store, { stableSessionId: id, walType: 98 })
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
})

test('source store: FTM9 flags0 terminalization is never CAPACITY and sticks', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x33)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id })
  const terminal = await terminalizeForwardHttpsSourceSessionV3(store, {
    stableSessionId: id,
    sequence: 2n,
    reason: 'CHAIN_INVALID',
    newTrustedEpochHighWatermark: 100
  })
  t.is(terminal.payload.byteLength, 192)
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.consumedUnprunedSlots, 1)
  await t.exception.all(appendForwardHttpsSourceSessionV3(store, { stableSessionId: id, walType: 97 }), /TERMINAL/)
  // Terminal PRUNE keeps the slot permanently consumed
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  slot.expiresAtEpoch = 1
  slot.recoveryGraceUntilEpoch = 1
  await pruneForwardHttpsSourceSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 200 })
  const after = forwardHttpsSourceStoreV3Status(store)
  t.is(after.consumedUnprunedSlots, 0)
  t.is(after.consumedPrunedSlots, 1)
  t.is(after.unconsumedSlots, after.slotCapacity - 1)
})

test('source store: FTM9 flags1 minimal absent-sequence terminal then terminal-only FPR9 count0', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x34)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  const result = await terminalizeForwardHttpsSourceAbsentSequenceV3(store, {
    stableSessionId: id,
    sequence: 5n,
    exactRequestCommitment: fixed(0x35),
    expiresAtEpoch: 1000,
    newTrustedEpochHighWatermark: 900
  })
  t.is(result.payload.byteLength, 192)
  t.is(result.payload.readUInt16BE(6), 1)
  t.is(result.payload.readUInt32BE(141), 1000)
  t.is(result.payload.readUInt32BE(145), 1900)
  // Grace not yet elapsed: pruneEpochSeconds must be strictly after 1900
  await t.exception.all(pruneForwardHttpsSourceSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 1900 }), /grace/)
  const pruned = await pruneForwardHttpsSourceSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 1901 })
  t.is(pruned.payload.byteLength, 256)
  t.is(pruned.payload.readUInt32BE(72), 0) // chargeEntryCount 0
  t.is(pruned.payload.readUInt32BE(76), 640) // beforeAuthorityBitmap bits7+9
  t.is(pruned.payload[84], 0) // NONE_CONSUMED
  t.is(pruned.payload[85], 2) // CONSUMED
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.consumedPrunedSlots, 1)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
  // Recovery reproduces the exact slot state
  await closeForwardHttpsSourceStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(reopened)
  t.is(recovered.consumedPrunedSlots, 1)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity - 1)
})

test('source store: nonterminal PRUNE releases the slot to FREE', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x36)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id })
  const pruned = await pruneForwardHttpsSourceSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 50 })
  t.is(pruned.payload[84], 1) // RELEASE_ALLOCATED
  t.is(pruned.payload[85], 1) // ALLOCATED
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity)
  await closeForwardHttpsSourceStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(reopened)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity)
})

test('source store: post-fsync adjust failure enters absorbing FAILED_PRUNE_DURABLE_PENDING', async t => {
  const r = await roots(t)
  let failAdjust = false
  const { authority, capabilities } = await quota(t, r, point => {
    if (failAdjust && point === 'ADJUST_AFTER_MEASURE') throw new Error('injected adjust failure')
  })
  const id = fixed(0x37)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceSessionV3(store, { stableSessionId: id })
  failAdjust = true
  await t.exception.all(pruneForwardHttpsSourceSessionV3(store, { stableSessionId: id, pruneEpochSeconds: 50 }), /FAILED_PRUNE_DURABLE_PENDING/)
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.state, 'FAILED_PRUNE_DURABLE_PENDING')
  t.absent(status.localOperational)
  // Every admission rejects; close is idempotent
  await t.exception.all(appendForwardHttpsSourceSessionV3(store, { stableSessionId: id, walType: 97 }))
  await closeForwardHttpsSourceStoreV3(store)
  await closeForwardHttpsSourceStoreV3(store)
  // Restart recovery applies the durable tombstone exactly once. The failed
  // authority is absorbing in-process; a fresh process recovers from a fresh
  // authority over the same roots.
  failAdjust = false
  const { authority: authority2, capabilities: capabilities2 } = await quota(t, r)
  const reopened = await openStore(authority2, r, capabilities2)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(reopened)
  t.is(recovered.state, 'OPEN')
  t.is(recovered.unconsumedSlots, recovered.slotCapacity)
})
