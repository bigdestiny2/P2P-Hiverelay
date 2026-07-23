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

// The operation final carries the exact same 32-byte requestCommitment at
// body offset 0 so recovery closes the prefix run exactly once.
function finalPayload (id, commitmentFill, fill = 0x54) {
  return b4a.concat([b4a.from('FTS3', 'ascii'), id, b4a.alloc(32, commitmentFill), b4a.alloc(8, fill)])
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
  return { authority, capabilities: mintForwardHttpsAggregateQuotaCapabilitiesV3(authority) }
}

async function quota2 (t, r) {
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
  return { authority, capabilities: mintForwardHttpsAggregateQuotaCapabilitiesV3(authority) }
}

// Every store operation passes the operational gate, so the quota authority
// must be OPEN: after the first store recovery completes, finish the other
// role's recovery and initialize exactly once per authority.
const initializedAuthorities = new Set()
async function openStore (authority, r, capabilities, overrides) {
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities, overrides))
  if (!initializedAuthorities.has(authority)) {
    initializedAuthorities.add(authority)
    const sink = beginForwardHttpsAggregateQuotaRecoveryV3(capabilities.sourceStoreQuotaCapability)
    const sourceFinal = await finishForwardHttpsAggregateQuotaRecoveryV3(sink)
    await initializeForwardHttpsAggregateQuotaV3(authority, { sourceRecoveryFinalState: sourceFinal, targetRecoveryFinalState: store.recoveryFinalState })
  }
  return store
}

async function directoryBytes (root) {
  let total = 0
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    const item = path.join(root, entry.name)
    if (entry.isDirectory()) total += await directoryBytes(item)
    else if (entry.isFile()) total += (await fs.lstat(item)).size
  }
  return total
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
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x51)
  const store = await openStore(authority, r, capabilities)
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
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const recoveredSlot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.registry.count, 3)
})

test('target store: minimal absent-sequence terminal and terminal-only prune', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x52)
  const store = await openStore(authority, r, capabilities)
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
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x54)
  const store = await openStore(authority, r, capabilities)
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
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x55)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  // A source WAL type can never be appended through the target store
  await t.exception.all(appendForwardHttpsTargetSessionV3(store, { stableSessionId: id, walType: 96 }), /not an ordinary target/)
})

test('prefix partition: FRESH type113 prefix claims exactly one PREFIX_ALLOCATED slot', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x56)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await rawAppend(store, 113, prefixPayload(id))
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
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
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x57)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id, body: b4a.alloc(8, 0x51) })
  const before = store.slots.get(b4a.toString(id, 'hex'))
  t.is(before.registry.count, 1)
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
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
  const { authority, capabilities } = await quota(t, r)
  const freshId = fixed(0x58)
  const existingId = fixed(0x59)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  // FRESH prefix completed by its matching final
  await rawAppend(store, 113, prefixPayload(freshId))
  await rawAppend(store, 112, finalPayload(freshId, 0x52))
  // EXISTING prefix completed by its matching final
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: existingId })
  await rawAppend(store, 113, prefixPayload(existingId))
  await rawAppend(store, 114, finalPayload(existingId, 0x52, 0x55))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
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
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x5a)
  // OPEN + target112 assigns PRESENT_ALLOCATED
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  t.is(identityOf(store.slots.get(b4a.toString(id, 'hex'))), IDENTITY.PRESENT_ALLOCATED)
  // +k complete target113 (no final, no abort) assigns ALLOCATED_WITH_PREFIX
  await rawAppend(store, 113, prefixPayload(id))
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(identityOf(slot), IDENTITY.ALLOCATED_WITH_PREFIX)
  t.is(slot.orphan.entries.length, 2)
  t.is(slot.orphan.removedSum, 920n)
})

test('flags2 abort goldens: remove-exactly-orphan, vector byte-identical, PRESENT_ALLOCATED continuity and retry', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x5c)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.state, SLOT.ALLOCATED_WITH_PREFIX)
  const beforeBitmap = slot.authorityBitmap
  // A later committed operation (no 113) is admitted while the prefix is open
  await appendForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, walType: 112, body: b4a.alloc(8, 0x5d) })
  t.is(slot.registry.count, 3)
  // The complete flags2 abort: ordinary net admission, exact orphan removal
  const aborted = await pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 2, pruneEpochSeconds: 8000 })
  t.is(aborted.payload.readUInt16BE(6), 2)
  t.is(aborted.payload.readUInt32BE(56), 0)
  t.is(aborted.payload.readUInt32BE(60), 0)
  t.is(aborted.payload.readUInt32BE(72), 1)
  t.is(aborted.payload[84], 2)
  t.is(aborted.payload[85], 1)
  // Carve-out: exactly the orphan entry removed, later entries preserved,
  // vector byte-identical, slot retained, identity stays PRESENT_ALLOCATED
  t.is(slot.state, SLOT.ALLOCATED)
  t.is(slot.orphan, null)
  t.is(slot.registry.count, 2, 'ordinary open entry plus the later committed entry')
  t.is(slot.authorityBitmap, beforeBitmap)
  t.absent(slot.prunedReleased)
  t.is(identityOf(slot), IDENTITY.PRESENT_ALLOCATED)
  // The mandated retry with fresh contiguous crypto revisions is admitted
  const retry = await appendForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, walType: 113, body: b4a.alloc(118 - 36, 0x5e) })
  t.is(retry.payload.byteLength, 118)
  t.is(slot.registry.count, 4)
  t.is(identityOf(slot), IDENTITY.PRESENT_ALLOCATED)
  // Recovery reclassifies the continuing session exactly once
  await closeForwardHttpsTargetStoreV3(reopened)
  const recovered = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(recovered).catch(() => {}) })
  const recoveredSlot = recovered.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.state, SLOT.ALLOCATED)
  t.is(recoveredSlot.orphan, null)
  t.is(recoveredSlot.registry.count, 4)
  t.is(identityOf(recoveredSlot), IDENTITY.PRESENT_ALLOCATED)
})

test('flags1 orphan abort: PREFIX_ALLOCATED to FREE, PRUNED_RELEASED and mutation-free CONFLICT after', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x5f)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await rawAppend(store, 113, prefixPayload(id))
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.state, SLOT.PREFIX_ALLOCATED)
  const aborted = await pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 1, pruneEpochSeconds: 7000 })
  t.is(aborted.payload.readUInt16BE(6), 1)
  t.is(aborted.payload.readUInt32BE(72), 2)
  t.is(aborted.payload[84], 1)
  t.is(aborted.payload[85], 3)
  t.is(slot.state, SLOT.FREE)
  t.is(slot.orphan, null)
  t.is(slot.registry.count, 0)
  t.ok(slot.prunedReleased)
  t.is(identityOf(slot), IDENTITY.PRUNED_RELEASED)
  const status = forwardHttpsTargetStoreV3Status(reopened)
  t.is(status.unconsumedSlots, status.slotCapacity)
  t.is(status.roleGlobalLogicalBytes, 736)
  // PRUNED_RELEASED returns mutation-free CONFLICT, never a NEVER_SEEN wedge
  let conflict = null
  try { await openForwardHttpsTargetSessionV3(reopened, { stableSessionId: id }) } catch (error) { conflict = error }
  t.is(conflict && conflict.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CONFLICT')
  t.is(forwardHttpsTargetStoreV3Status(reopened).unconsumedSlots, status.slotCapacity, 'no mutation from the CONFLICT')
  // flags1/flags2 variants require their exact slot states
  await t.exception.all(pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 1, pruneEpochSeconds: 7001 }), /requires a fresh recovered prefix/)
  await t.exception.all(pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 2, pruneEpochSeconds: 7001 }), /requires an existing-session prefix/)
})

test('prefix-abort ordinary admission: exact inequality equality admits, ceiling+1 CAPACITY with zero mutation', async t => {
  // Each case builds its own crashed-prefix WAL so the equality admission
  // cannot mutate the evidence for the ceiling+1 case.
  for (const equality of [true, false]) {
    const r = await roots(t)
    const { authority, capabilities } = await quota2(t, r)
    const id = fixed(0x60)
    const store = await openStore(authority, r, capabilities)
    await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
    await rawAppend(store, 113, prefixPayload(id))
    await closeForwardHttpsTargetStoreV3(store)
    const measured = await directoryBytes(r['target-store'])
    // The abort-time role logical: the committed open-frame charge from the
    // ledger plus the raw orphan type113 frame's exact 460 charge, which the
    // recovery replay seeds authoritatively.
    const roleLogical = forwardHttpsAggregateQuotaV3Status(authority).targetLogicalChargedBytes + 460
    await closeForwardHttpsAggregateQuotaV3(authority)
    // Exact boundary: current physical + 480 planned + one unconsumed identity
    // at 896, and the seeded role logical plus net 276 plus the 1344
    // unconsumed liability, against the per-store ceiling.
    const perStore = Math.max(measured + 480 + 896, roleLogical + 276 + 1344) - (equality ? 0 : 1)
    const authority2 = await openForwardHttpsAggregateQuotaV3({
      sourceReplayRoot: r['source-replay'],
      targetReplayRoot: r['target-replay'],
      sourceStoreRoot: r['source-store'],
      targetStoreRoot: r['target-store'],
      maximumDurableBytesPerStore: perStore,
      maximumForwardStorageBytesAggregate: 2 * perStore,
      monotonicMillis: () => Date.now(),
      callbackTimeoutMillis: 15000,
      faultInjector: null
    })
    t.teardown(async () => { await closeForwardHttpsAggregateQuotaV3(authority2).catch(() => {}) })
    const capabilities2 = mintForwardHttpsAggregateQuotaCapabilitiesV3(authority2)
    const reopened = await openStore(authority2, r, capabilities2, {
      limits: {
        maximumRetainedTurnsPerRole: 1,
        maximumDurableBytesPerStore: perStore,
        maximumForwardStorageBytesAggregate: 2 * perStore
      }
    })
    const slot = reopened.slots.get(b4a.toString(id, 'hex'))
    t.is(slot.state, SLOT.ALLOCATED_WITH_PREFIX)
    const headBefore = forwardHttpsTargetStoreV3Status(reopened).walHeadSequence
    if (equality) {
      const aborted = await pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 2, pruneEpochSeconds: 9000 })
      t.is(aborted.payload.readUInt16BE(6), 2)
      t.is(slot.state, SLOT.ALLOCATED)
      t.is(identityOf(slot), IDENTITY.PRESENT_ALLOCATED)
    } else {
      let denied = null
      try { await pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 2, pruneEpochSeconds: 9000 }) } catch (error) { denied = error }
      t.is(denied && denied.code, 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_CAPACITY')
      // Zero mutation: WAL head, slot, orphan and registry are all unchanged
      t.is(forwardHttpsTargetStoreV3Status(reopened).walHeadSequence, headBefore)
      t.is(slot.state, SLOT.ALLOCATED_WITH_PREFIX)
      t.is(slot.registry.count, 2)
      t.is(slot.orphan.entries.length, 1)
      t.is(forwardHttpsTargetStoreV3Status(reopened).roleGlobalLogicalBytes, 0)
    }
    await closeForwardHttpsTargetStoreV3(reopened)
  }
})

test('flags2 abort requires an open existing-session prefix; mixed commitment is INTEGRITY', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x61)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  // flags2 on a plain ALLOCATED session (no open prefix) rejects
  await t.exception.all(pruneForwardHttpsTargetSessionV3(store, { stableSessionId: id, flags: 2, pruneEpochSeconds: 100 }), /requires an existing-session prefix/)
  // A mixed requestCommitment inside one run is INTEGRITY in recovery
  await rawAppend(store, 113, prefixPayload(id, 0x52))
  await rawAppend(store, 113, prefixPayload(id, 0x53))
  await closeForwardHttpsTargetStoreV3(store)
  await t.exception.all(openStore(authority, r, capabilities), /mixed prefix requestCommitment|INTEGRITY/)
})

test('overlay terminalization: flags0 on ALLOCATED_WITH_PREFIX with orphan persistence and no flags2 after', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x62)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const slot = reopened.slots.get(b4a.toString(id, 'hex'))
  t.is(slot.state, SLOT.ALLOCATED_WITH_PREFIX)
  t.is(slot.orphan.lastRevision, 2n)
  // flags0 SESSION_TERMINAL uses the exact orphan-last revision floor,
  // preserves the vector and moves the slot to CONSUMED_UNPRUNED
  const terminal = await terminalizeForwardHttpsTargetSessionV3(reopened, {
    stableSessionId: id,
    sequence: 7n,
    reason: 'CHAIN_INVALID',
    newTrustedEpochHighWatermark: 9
  })
  t.is(terminal.payload.readUInt16BE(6), 0)
  t.is(Number(terminal.payload.readBigUInt64BE(64)), 2)
  t.is(slot.state, SLOT.CONSUMED_UNPRUNED)
  t.is(slot.orphan, null)
  t.is(slot.registry.count, 2, 'orphan entries persist into the consumed registry')
  t.is(identityOf(slot), IDENTITY.PRESENT_CONSUMED_UNPRUNED)
  // No flags2 abort is possible after terminalization
  await t.exception.all(pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, flags: 2, pruneEpochSeconds: 9500 }), /requires an existing-session prefix/)
  // The later terminal-existing FPR9 removes the persisted orphan entries
  const pruned = await pruneForwardHttpsTargetSessionV3(reopened, { stableSessionId: id, pruneEpochSeconds: 9600 })
  t.is(pruned.payload.readUInt32BE(72), 2)
  t.is(slot.state, SLOT.CONSUMED_PRUNED)
  // Recovery reproduces the exact consumed-pruned disposition
  await closeForwardHttpsTargetStoreV3(reopened)
  const recovered = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(recovered).catch(() => {}) })
  const recoveredSlot = recovered.slots.get(b4a.toString(id, 'hex'))
  t.is(recoveredSlot.state, SLOT.CONSUMED_PRUNED)
  t.is(identityOf(recoveredSlot), IDENTITY.PRUNED_CONSUMED)
})

test('store-level precedence: PRESENT_PREFIX_ALLOCATED is SESSION_CLOSED, consumed is TERMINAL, pruned is CONFLICT', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const prefixId = fixed(0x63)
  const consumedId = fixed(0x64)
  const prunedId = fixed(0x65)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  // PREFIX_ALLOCATED: mutation-free SESSION_CLOSED before any other work
  await rawAppend(store, 113, prefixPayload(prefixId))
  // consumed identity: sticky TERMINAL
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: consumedId })
  await terminalizeForwardHttpsTargetSessionV3(store, { stableSessionId: consumedId, sequence: 3n, reason: 'CHAIN_INVALID' })
  // pruned identity: CONFLICT
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: prunedId })
  await pruneForwardHttpsTargetSessionV3(store, { stableSessionId: prunedId, pruneEpochSeconds: 500 })
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  t.is(identityOf(reopened.slots.get(b4a.toString(prefixId, 'hex'))), IDENTITY.PRESENT_PREFIX_ALLOCATED)
  const headBefore = forwardHttpsTargetStoreV3Status(reopened).walHeadSequence
  let sessionClosed = null
  try { await appendForwardHttpsTargetSessionV3(reopened, { stableSessionId: prefixId, walType: 112 }) } catch (error) { sessionClosed = error }
  t.is(sessionClosed && sessionClosed.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SESSION_CLOSED')
  let terminal = null
  try { await appendForwardHttpsTargetSessionV3(reopened, { stableSessionId: consumedId, walType: 112 }) } catch (error) { terminal = error }
  t.is(terminal && terminal.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_TERMINAL')
  let conflict = null
  try { await appendForwardHttpsTargetSessionV3(reopened, { stableSessionId: prunedId, walType: 112 }) } catch (error) { conflict = error }
  t.is(conflict && conflict.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CONFLICT')
  // All three rejections are mutation-free
  t.is(forwardHttpsTargetStoreV3Status(reopened).walHeadSequence, headBefore)
})

test('matching-final wrong-operation: non-matching final on a fresh prefix is INTEGRITY, never admitted', async t => {
  const r = await roots(t)
  const { capabilities } = await quota(t, r)
  const id = fixed(0x66)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await rawAppend(store, 113, prefixPayload(id))
  // A final of a DIFFERENT operation (different requestCommitment) follows
  await rawAppend(store, 112, finalPayload(id, 0x53))
  await closeForwardHttpsTargetStoreV3(store)
  // Recovery has exactly one disposition: INTEGRITY, never an admission
  await t.exception.all(openForwardHttpsTargetStoreV3(storeOptions(r, capabilities)), /non-matching final|INTEGRITY/)
})

test('recovered tombstone tamper: count and commitment mismatches are INTEGRITY at recovery', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x67)
  const store = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await openForwardHttpsTargetSessionV3(store, { stableSessionId: id })
  const slot = store.slots.get(b4a.toString(id, 'hex'))
  const { encodeForwardHttpsRetentionPrunedV3 } = await import('../forward-https-replay-journal-v4.js')
  const base = {
    role: 'TARGET_STORE',
    stableSessionId: id,
    priorSessionRevision: slot.priorRevision,
    pruneEpochSeconds: 500,
    trustedEpochHighWatermark: 500,
    expiresAtEpoch: slot.expiresAtEpoch,
    recoveryGraceUntilEpoch: slot.recoveryGraceUntilEpoch,
    removedOrdinaryLogicalBytes: slot.registry.removedLogicalBytes(),
    chargeEntryCount: slot.registry.count,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 1,
    terminalSlotState: 1,
    chargeEntryBuffers: slot.registry.entriesAscending(),
    authorityCommitments: Array.from({ length: 10 }, () => b4a.alloc(32))
  }
  // count=2 against a 1-entry registry (review probe)
  const countTampered = encodeForwardHttpsRetentionPrunedV3({ ...base, chargeEntryCount: 1 })
  countTampered.writeUInt32BE(2, 72)
  await rawAppend(store, 118, countTampered)
  await closeForwardHttpsTargetStoreV3(store)
  await t.exception.all(openForwardHttpsTargetStoreV3(storeOptions(r, capabilities)), /independently match|INTEGRITY/)
})

test('fresh OPEN on PRESENT_PREFIX_ALLOCATED is mutation-free SESSION_CLOSED', async t => {
  const r = await roots(t)
  const { authority, capabilities } = await quota(t, r)
  const id = fixed(0x68)
  const store = await openForwardHttpsTargetStoreV3(storeOptions(r, capabilities))
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(store).catch(() => {}) })
  await rawAppend(store, 113, prefixPayload(id))
  await closeForwardHttpsTargetStoreV3(store)
  const reopened = await openStore(authority, r, capabilities)
  t.teardown(async () => { await closeForwardHttpsTargetStoreV3(reopened).catch(() => {}) })
  const headBefore = forwardHttpsTargetStoreV3Status(reopened).walHeadSequence
  let closed = null
  try { await openForwardHttpsTargetSessionV3(reopened, { stableSessionId: id }) } catch (error) { closed = error }
  t.is(closed && closed.code, 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SESSION_CLOSED')
  t.is(forwardHttpsTargetStoreV3Status(reopened).walHeadSequence, headBefore)
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
