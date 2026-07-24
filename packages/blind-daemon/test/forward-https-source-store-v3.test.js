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
  initializeForwardHttpsAggregateQuotaV3,
  createForwardHttpsStoreQuotaCostPlanV3,
  reserveForwardHttpsAggregateQuotaV3,
  bindForwardHttpsStoreQuotaActualBuffersV3,
  applyForwardHttpsAggregateQuotaWalFrameV3,
  commitForwardHttpsAggregateQuotaV3,
  releaseForwardHttpsAggregateQuotaV3,
  adjustForwardHttpsAggregateQuotaV3,
  forwardHttpsAggregateQuotaV3Status,
  encodeForwardHttpsRetentionPrunedV3
} from '../forward-https-replay-journal-v4.js'
import {
  openForwardHttpsSourceStoreV3,
  prepareForwardHttpsSourceTurnV3,
  persistForwardHttpsSourceResultV3,
  forwardHttpsSourceStoreV3Status,
  closeForwardHttpsSourceStoreV3,
  FORWARD_HTTPS_SOURCE_WAL_TYPE,
  FORWARD_HTTPS_SOURCE_STORE_V3_STATUS,
  FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT
} from '../forward-https-source-store-v3.js'

function fixed (byte) {
  return b4a.alloc(32, byte)
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
  output[offset++] = 1
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

// Quota-API drivers: terminal append through the composite, prune through
// bind/apply/adjust, both with caller-supplied exact payloads.
async function driveWal (store, operation, frames) {
  const plan = createForwardHttpsStoreQuotaCostPlanV3(store.storeQuotaCapability, {
    operation,
    knownInputBuffers: frames.map(frame => frame.payload),
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await reserveForwardHttpsAggregateQuotaV3(store.storeQuotaCapability, plan)
  const reservation = union.reservation || union.terminalReservation
  let attempted = false
  try {
    const { transitionAuthority } = bindForwardHttpsStoreQuotaActualBuffersV3(store.storeQuotaCapability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: frames.slice(0, -1).map(frame => frame.payload),
      finalWalMetadataBuffers: [frames[frames.length - 1].payload],
      temporaryWriteBuffers: []
    })
    attempted = true
    let claimOrHandoff = transitionAuthority
    let entry = null
    for (const candidate of frames) {
      const applied = await applyForwardHttpsAggregateQuotaWalFrameV3(store.storeQuotaCapability, reservation, claimOrHandoff, candidate,
        async frame => store.store.appendAndApply(frame, () => {}))
      entry = applied.entry
      claimOrHandoff = applied.transitionAuthorityHandoff
    }
    return { entry, reservation }
  } catch (error) {
    if (!attempted) await releaseForwardHttpsAggregateQuotaV3(store.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
}

async function driveTerminal (store, payload) {
  const { entry, reservation } = await driveWal(store, 'SESSION_TERMINAL', [{
    type: 99,
    transactionId: b4a.alloc(32, 0x5a),
    virtualBucket: 0,
    payload
  }])
  await commitForwardHttpsAggregateQuotaV3(store.storeQuotaCapability, reservation, {
    durableWalHeadSequence: store.store.walSequence,
    durableWalHeadHash: store.store.walHash
  })
  return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(store.store.walHash), payload })
}

async function drivePrune (store, payload) {
  const { entry } = await driveWal(store, 'PRUNE', [{
    type: 100,
    transactionId: b4a.alloc(32, 0x5a),
    virtualBucket: 0,
    payload
  }])
  await adjustForwardHttpsAggregateQuotaV3(store.storeQuotaCapability, {
    durableTombstonePayloadBuffer: payload,
    durableWalHeadSequence: store.store.walSequence,
    durableWalHeadHash: store.store.walHash
  })
  return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(store.store.walHash), payload })
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
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
  const store = await openForwardHttpsSourceStoreV3(storeOptions(r, capabilities, { sourceQuotaRecoverySink: sink, ...overrides }))
  const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  if (!initializedAuthorities.has(authority)) {
    initializedAuthorities.add(authority)
    const targetSink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.targetStoreQuotaCapability)
    const targetFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(targetSink)
    await initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: targetFinal })
  }
  return store
}

const PLACEHOLDER_JOURNAL = Object.freeze({})

function storeOptions (r, capabilities, overrides = {}) {
  return {
    root: r['source-store'],
    replayJournalAuthority: PLACEHOLDER_JOURNAL,
    sourceStoreQuotaCapability: capabilities.sourceStoreQuotaCapability,
    wireV3AbiHash: fixed(0x24),
    privateIpcV4Hash: fixed(0x25),
    signedLaunchTopologyHash: fixed(0x26),
    storeId: fixed(0x21),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x22),
    durabilityContinuityHash: fixed(0x23),
    epochSeconds: () => 1000000,
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
  const prepared = await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id, body: b4a.alloc(16, 0x41) })
  t.is(prepared.walSequence, 1n)
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
  await persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: FORWARD_HTTPS_SOURCE_WAL_TYPE.TRANSPORT_RESERVED, body: b4a.alloc(4, 0x42) })
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
  await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id })
  await t.exception.all(prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id }), /not NEVER_SEEN/)
  // Later sequences reuse the same ALLOCATED slot: no additional slot is consumed
  await persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: 97 })
  await persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: 98 })
  const status = forwardHttpsSourceStoreV3Status(store)
  t.is(status.unconsumedSlots, status.slotCapacity - 1)
})

test('source store: FTM9 flags0 terminalization is never CAPACITY and sticks', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x33)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id })
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  const terminal = await driveTerminal(store, buildFtm9({
    flags: 0,
    stableSessionId: id,
    sequence: 2n,
    priorSessionRevision: slot.priorRevision,
    newTrustedEpochHighWatermark: 100,
    reason: 'CHAIN_INVALID'
  }))
  t.is(terminal.payload.byteLength, 192)
  // The durable terminal reclassifies on recovery; live work is then TERMINAL.
  await closeForwardHttpsSourceStoreV3(store)
  const recoveredStore = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(recoveredStore).catch(() => {}) })
  const recoveredSlot = recoveredStore.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.state, 'CONSUMED_UNPRUNED')
  await t.exception.all(persistForwardHttpsSourceResultV3(recoveredStore, { stableSessionId: id, walType: 97 }), /TERMINAL/)
  // Terminal PRUNE keeps the slot permanently consumed
  const fpr9 = encodeForwardHttpsRetentionPrunedV3({
    role: 'SOURCE_STORE',
    stableSessionId: id,
    priorSessionRevision: recoveredSlot.priorRevision,
    pruneEpochSeconds: 200,
    trustedEpochHighWatermark: 200,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: recoveredSlot.registry.removedLogicalBytes(),
    chargeEntryCount: recoveredSlot.registry.count,
    beforeAuthorityBitmap: recoveredSlot.authorityBitmap,
    allocationDisposition: 0,
    terminalSlotState: 2,
    chargeEntryBuffers: recoveredSlot.registry.entriesAscending(),
    authorityCommitments: recoveredSlot.authorityCommitments || Array.from({ length: 10 }, () => b4a.alloc(32))
  })
  await drivePrune(recoveredStore, fpr9)
  await closeForwardHttpsSourceStoreV3(recoveredStore)
  const finalStore = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(finalStore).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(finalStore)
  t.is(recovered.consumedUnprunedSlots, 0)
  t.is(recovered.consumedPrunedSlots, 1)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity - 1)
})

test('source store: FTM9 flags1 minimal absent-sequence terminal then terminal-only FPR9 count0', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x34)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  const result = await driveTerminal(store, buildFtm9({
    flags: 1,
    stableSessionId: id,
    sequence: 5n,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: 900,
    reason: 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: fixed(0x35),
    expiresAtEpoch: 1000,
    retainedUntilEpoch: 1900
  }))
  t.is(result.payload.byteLength, 192)
  t.is(result.payload.readUInt16BE(6), 1)
  t.is(result.payload.readUInt32BE(141), 1000)
  t.is(result.payload.readUInt32BE(145), 1900)
  // Grace not yet elapsed: pruneEpochSeconds must be strictly after 1900.
  // The FPR9 fields come from the recovered mirror state after reopen.
  await closeForwardHttpsSourceStoreV3(store)
  const recovered1 = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(recovered1).catch(() => {}) })
  const slot = recovered1.slots.get(b4a.toString(id, 'hex'))
  const fpr9 = epoch => encodeForwardHttpsRetentionPrunedV3({
    role: 'SOURCE_STORE',
    stableSessionId: id,
    priorSessionRevision: slot.priorRevision,
    pruneEpochSeconds: epoch,
    trustedEpochHighWatermark: Math.max(slot.trustedEpochHighWatermark, epoch),
    expiresAtEpoch: slot.expiresAtEpoch,
    recoveryGraceUntilEpoch: slot.recoveryGraceUntilEpoch,
    removedOrdinaryLogicalBytes: 0n,
    chargeEntryCount: 0,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 0,
    terminalSlotState: 2,
    chargeEntryBuffers: [],
    authorityCommitments: slot.authorityCommitments
  })
  await t.exception.all(drivePrune(recovered1, fpr9(1900)), /recovery grace|INTEGRITY/)
  const pruned = await drivePrune(recovered1, fpr9(1901))
  t.is(pruned.payload.byteLength, 256)
  t.is(pruned.payload.readUInt32BE(72), 0) // chargeEntryCount 0
  t.is(pruned.payload.readUInt32BE(76), 640) // beforeAuthorityBitmap bits7+9
  t.is(pruned.payload[84], 0) // NONE_CONSUMED
  t.is(pruned.payload[85], 2) // CONSUMED
  // Recovery reproduces the exact slot state
  await closeForwardHttpsSourceStoreV3(recovered1)
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
  await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id })
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  const fpr9 = encodeForwardHttpsRetentionPrunedV3({
    role: 'SOURCE_STORE',
    stableSessionId: id,
    priorSessionRevision: slot.priorRevision,
    pruneEpochSeconds: 50,
    trustedEpochHighWatermark: 50,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: slot.registry.removedLogicalBytes(),
    chargeEntryCount: slot.registry.count,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: slot.registry.entriesAscending(),
    authorityCommitments: Array.from({ length: 10 }, () => b4a.alloc(32))
  })
  const pruned = await drivePrune(store, fpr9)
  t.is(pruned.payload[84], 1) // RELEASE_ALLOCATED
  t.is(pruned.payload[85], 1) // ALLOCATED
  await closeForwardHttpsSourceStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  const recovered = forwardHttpsSourceStoreV3Status(reopened)
  t.is(recovered.unconsumedSlots, recovered.slotCapacity)
})

test('open ABI: source exact required key set enforced', async t => {
  const r = await roots(t)
  const { capabilities } = await quota(t, r)
  t.is(Object.keys(FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT).length, 11)
  const good = storeOptions(r, capabilities)
  const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
  const store = await openForwardHttpsSourceStoreV3({ ...good, sourceQuotaRecoverySink: sink })
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
  for (const key of ['replayJournalAuthority', 'sourceStoreQuotaCapability', 'wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'epochSeconds', 'monotonicMillis']) {
    const missing = { ...good }
    delete missing[key]
    const attempt = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
    await t.exception.all(openForwardHttpsSourceStoreV3({ ...missing, sourceQuotaRecoverySink: attempt }), new RegExp(key))
    await finishForwardHttpsAggregateQuotaRecoveryV3(attempt)
  }
  const noSink = { ...good }
  delete noSink.sourceQuotaRecoverySink
  await t.exception.all(openForwardHttpsSourceStoreV3(noSink), /sourceQuotaRecoverySink/)
  await t.exception.all(openForwardHttpsSourceStoreV3({ ...good, sourceQuotaRecoverySink: sink, bogusKey: 1 }), /unknown field/)
})

test('source store: post-fsync adjust failure transitions the quota to absorbing FAILED_WAL', async t => {
  const r = await roots(t)
  let failAdjust = false
  const { authority, capabilities } = await quota(t, r, point => {
    if (failAdjust && point === 'ADJUST_AFTER_MEASURE') throw new Error('injected adjust failure')
  })
  const id = fixed(0x37)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id })
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  const fpr9 = encodeForwardHttpsRetentionPrunedV3({
    role: 'SOURCE_STORE',
    stableSessionId: id,
    priorSessionRevision: slot.priorRevision,
    pruneEpochSeconds: 50,
    trustedEpochHighWatermark: 50,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: slot.registry.removedLogicalBytes(),
    chargeEntryCount: slot.registry.count,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: slot.registry.entriesAscending(),
    authorityCommitments: Array.from({ length: 10 }, () => b4a.alloc(32))
  })
  failAdjust = true
  // The tombstone is durable; the adjust fault transitions the quota authority
  // to absorbing FAILED_WAL_OUTCOME_UNKNOWN_PENDING with no retry in-process.
  await t.exception.all(drivePrune(store, fpr9), /failed|INTEGRITY/)
  const failed = forwardHttpsAggregateQuotaV3Status(authority)
  t.is(failed.state, 'FAILED_WAL_OUTCOME_UNKNOWN_PENDING')
  t.absent(failed.localOperational)
  // Every admission rejects; close is idempotent
  await t.exception.all(persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: 97 }))
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

test('fault registry: OPEN_AFTER_RECOVERY and CLOSE_BEFORE_STORE_CLOSE fire with coded errors', async t => {
  // The module-level points fire alongside the engine points on a plain
  // open/close lifecycle.
  const r1 = await roots(t)
  const { authority: a1, capabilities: c1 } = await quota(t, r1)
  const observed = []
  const contexts = []
  const store = await openStore(a1, r1, c1, { faultInjector: async (point, context) => { observed.push(point); contexts.push(context) } })
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  t.ok(observed.includes(FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.OPEN_AFTER_RECOVERY), 'open fault point fired')
  await closeForwardHttpsSourceStoreV3(store)
  t.ok(observed.includes(FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.CLOSE_BEFORE_STORE_CLOSE), 'close fault point fired')
  // Only the module's frozen points reach the caller, never raw engine points
  // or a context argument.
  t.ok(observed.every(point => Object.values(FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT).includes(point)), 'no raw engine points escape')
  t.ok(contexts.every(context => context === undefined), 'no context is passed')
  // Open fault: the injector failure is a coded INTEGRITY rejection of open
  // with no live engine left behind.
  const r2 = await roots(t)
  const { authority: a2, capabilities: c2 } = await quota(t, r2)
  await t.exception.all(openStore(a2, r2, c2, {
    faultInjector: async point => {
      if (point === FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.OPEN_AFTER_RECOVERY) throw new Error('injected open fault')
    }
  }), /fault injector failed at OPEN_AFTER_RECOVERY|INTEGRITY/)
  // A non-undefined injector return maps to coded INTEGRITY as well.
  const r2b = await roots(t)
  const { authority: a2b, capabilities: c2b } = await quota(t, r2b)
  await t.exception.all(openStore(a2b, r2b, c2b, {
    faultInjector: async point => {
      if (point === FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.OPEN_AFTER_RECOVERY) return 'injected'
      return undefined
    }
  }), /returned a value|INTEGRITY/)
  // Close fault: the first close reports coded INTEGRITY, the store still
  // reaches CLOSED with blocker INTEGRITY and the exact-owner repeat resolves.
  const r3 = await roots(t)
  const { authority: a3, capabilities: c3 } = await quota(t, r3)
  const store3 = await openStore(a3, r3, c3, {
    faultInjector: async point => {
      if (point === FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.CLOSE_BEFORE_STORE_CLOSE) throw new Error('injected close fault')
    }
  })
  let closeError = null
  try {
    await closeForwardHttpsSourceStoreV3(store3)
  } catch (error) {
    closeError = error
  }
  t.ok(closeError, 'the first close reports the fault')
  t.is(closeError.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INTEGRITY')
  t.is(store3.closed, true)
  t.is(forwardHttpsSourceStoreV3Status(store3).blocker, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INTEGRITY')
  await closeForwardHttpsSourceStoreV3(store3)
})

test('readiness flags: the source store STATUS constant is not implementation-ready', async t => {
  t.is(FORWARD_HTTPS_SOURCE_STORE_V3_STATUS.implementationReady, false)
  t.is(FORWARD_HTTPS_SOURCE_STORE_V3_STATUS.runtimeReady, false)
  t.is(FORWARD_HTTPS_SOURCE_STORE_V3_STATUS.releaseReady, false)
  t.is(FORWARD_HTTPS_SOURCE_STORE_V3_STATUS.authorizesRelease, false)
})

test('wired cap+1 terminal conversion: the 65535-entry source session ends CONSUMED_UNPRUNED on reopen (required_tests[15])', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x6e)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  // Seed 65536 charge entries through raw WAL appends (group-committed): the
  // exact cap is legal; the next entry exceeds it.
  const seedPayload = b4a.concat([b4a.from('FSS3', 'ascii'), id, b4a.alloc(8, 0x51)])
  for (let chunk = 0; chunk * 500 < 65536; chunk++) {
    const appends = []
    for (let index = 0; index < 500 && chunk * 500 + index < 65536; index++) {
      appends.push(store.store.appendAndApply({ type: 96, transactionId: b4a.alloc(32, 0x66), virtualBucket: 0, payload: seedPayload }, () => {}))
    }
    await Promise.all(appends)
  }
  await closeForwardHttpsSourceStoreV3(store)
  const seeded = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(seeded).catch(() => {}) })
  t.is(seeded.slots.get(b4a.toString(id, 'hex')).registry.count, 65536)
  // The wired persist at cap+1 terminalizes through the ENTRY_CAP arm, then
  // surfaces BUDGET_EXHAUSTED to the caller.
  await t.exception.all(persistForwardHttpsSourceResultV3(seeded, { stableSessionId: id, walType: 97 }), /BUDGET_EXHAUSTED|cap exceeded/)
  t.is(seeded.slots.get(b4a.toString(id, 'hex')).state, 'CONSUMED_UNPRUNED')
  await closeForwardHttpsSourceStoreV3(seeded)
  // On reopen the session is durably CONSUMED_UNPRUNED and the terminal
  // identity is sticky mutation-free.
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(reopened).catch(() => {}) })
  t.is(reopened.slots.get(b4a.toString(id, 'hex')).state, 'CONSUMED_UNPRUNED')
  await t.exception.all(persistForwardHttpsSourceResultV3(reopened, { stableSessionId: id, walType: 97 }), /TERMINAL/)
})

test('planned hint above the exact operation row rejects at the boundary with zero mutation (probe w1)', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x71)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsSourceStoreV3(store).catch(() => {}) })
  await prepareForwardHttpsSourceTurnV3(store, { stableSessionId: id, body: b4a.alloc(4, 0x51) })
  const headBefore = forwardHttpsSourceStoreV3Status(store).walHeadSequence
  // plannedRemovableChargeEntryCount=65536 on a healthy session: rejected at
  // the boundary before any reservation or WAL mutation (REREVIEW3-P1-001
  // probe (i)).
  await t.exception.all(
    persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: 97, plannedRemovableChargeEntryCount: 65536 }),
    /exceeds the exact operation row|TypeError/
  )
  t.is(forwardHttpsSourceStoreV3Status(store).walHeadSequence, headBefore)
  t.absent(forwardHttpsAggregateQuotaV3Status(authority).pendingReservation)
  await persistForwardHttpsSourceResultV3(store, { stableSessionId: id, walType: 97 })
  await closeForwardHttpsSourceStoreV3(store)
  await closeForwardHttpsAggregateQuotaV3(authority)
  t.is(forwardHttpsAggregateQuotaV3Status(authority).state, 'CLOSED')
})
