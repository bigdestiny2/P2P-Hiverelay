// Kill fixture for FORWARD HTTPS durability storage v3 child-process tests.
// Usage: node forward-https-storage-kill-fixture.mjs <mode> <baseDir>
// Modes:
//   setup    — create the four quota roots, open quota+target store, create one
//              session, print the minted identities as JSON, exit cleanly.
//   crash    — reopen, append a durable FPR9 tombstone payload directly through
//              the child store WAL, then process.exit(2) BEFORE any in-memory
//              prune application, simulating a crash after complete fsync.
//   verify   — reopen fresh and print the recovered slot/head state as JSON;
//              the durable tombstone must be applied exactly once.

import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import {
  openForwardHttpsAggregateQuotaV3,
  mintForwardHttpsAggregateQuotaCapabilitiesV3,
  closeForwardHttpsAggregateQuotaV3,
  encodeForwardHttpsRetentionPrunedV3
} from '../forward-https-replay-journal-v4.js'
import {
  openForwardHttpsTargetStoreV3,
  openForwardHttpsTargetSessionV3,
  forwardHttpsTargetStoreV3Status,
  closeForwardHttpsTargetStoreV3
} from '../forward-https-target-store-v3.js'

const [mode, base] = process.argv.slice(2)
if (!mode || !base) {
  console.error('usage: fixture <setup|crash|verify> <baseDir>')
  process.exit(64)
}

function fixed (byte) {
  return b4a.alloc(32, byte)
}

async function main () {
  const roots = {}
  for (const name of ['source-replay', 'target-replay', 'source-store', 'target-store']) {
    roots[name] = path.join(base, name)
    await fs.mkdir(roots[name], { recursive: true, mode: 0o700 })
  }
  const quotaAuthority = await openForwardHttpsAggregateQuotaV3({
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
  const capabilities = mintForwardHttpsAggregateQuotaCapabilitiesV3(quotaAuthority)
  const id = fixed(0x61)
  const options = {
    root: roots['target-store'],
    storeQuotaCapability: capabilities.targetStoreQuotaCapability,
    storeId: fixed(0x62),
    mapGeneration: 1n,
    ownerFenceTokenHash: fixed(0x63),
    durabilityContinuityHash: fixed(0x64),
    monotonicMillis: () => Date.now()
  }
  const store = await openForwardHttpsTargetStoreV3(options)
  if (mode === 'setup') {
    const opened = await openForwardHttpsTargetSessionV3(store, { stableSessionId: id, body: b4a.alloc(4, 0x65) })
    console.log(JSON.stringify({ walSequence: opened.walSequence.toString() }))
    await closeForwardHttpsTargetStoreV3(store)
    await closeForwardHttpsAggregateQuotaV3(quotaAuthority)
    return
  }
  if (mode === 'crash') {
    // Durable FPR9 tombstone through the child WAL, then die before in-memory apply.
    const slot = store.slots.get(b4a.toString(id, 'hex'))
    const payload = encodeForwardHttpsRetentionPrunedV3({
      role: 'TARGET_STORE',
      stableSessionId: id,
      priorSessionRevision: slot.priorRevision,
      pruneEpochSeconds: 60,
      trustedEpochHighWatermark: 60,
      expiresAtEpoch: 0,
      recoveryGraceUntilEpoch: 0,
      removedOrdinaryLogicalBytes: slot.registry.removedLogicalBytes(),
      chargeEntryCount: slot.registry.count,
      beforeAuthorityBitmap: 0,
      allocationDisposition: 1,
      terminalSlotState: 1,
      chargeEntryBuffers: slot.registry.entriesAscending(),
      authorityCommitments: Array.from({ length: 10 }, () => b4a.alloc(32))
    })
    await store.store.appendAndApply({
      type: 118,
      transactionId: b4a.alloc(32, 0x66),
      virtualBucket: 0,
      payload
    }, () => {})
    process.exit(2)
  }
  if (mode === 'verify') {
    const status = forwardHttpsTargetStoreV3Status(store)
    const slot = store.slots.get(b4a.toString(id, 'hex'))
    console.log(JSON.stringify({
      state: status.state,
      walHeadSequence: status.walHeadSequence.toString(),
      unconsumedSlots: status.unconsumedSlots,
      slotCapacity: status.slotCapacity,
      slotState: slot ? slot.state : null,
      prunedReleased: slot ? slot.prunedReleased : null
    }))
    await closeForwardHttpsTargetStoreV3(store)
    await closeForwardHttpsAggregateQuotaV3(quotaAuthority)
    return
  }
  console.error(`unknown mode ${mode}`)
  process.exit(64)
}

main().catch(error => {
  console.error(error && error.stack ? error.stack : String(error))
  process.exit(1)
})
