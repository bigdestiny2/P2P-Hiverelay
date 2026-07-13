import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import { PRIVATE_IPC_V2_REPLAY_POLICY } from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import {
  PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS,
  PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS,
  closePrivateIpcReplayJournalV2,
  consumePrivateIpcReplayReservationV2,
  openPrivateIpcReplayJournalV2,
  privateIpcReplayJournalV2Status,
  reservePrivateIpcReplayTupleV2
} from '../private-ipc-replay-journal-v2.js'

const JOURNAL_FILE = 'replay-journal.v2'
const LOCK_FILE = 'writer.lock.v2'
const SCRATCH_ROOT = path.resolve('.t')

function fixed (byte) {
  return b4a.alloc(32, byte)
}

function journalOptions (root, clock, overrides = {}) {
  return {
    root,
    launchTopologyHash: fixed(0x11),
    relayPublicKey: fixed(0x12),
    storeId: fixed(0x13),
    durabilityContinuityHash: fixed(0x14),
    durabilityProfileHash: fixed(0x15),
    storeFormatHash: fixed(0x16),
    mapGeneration: 7n,
    ownerFenceTokenHash: fixed(0x17),
    partitionKey: fixed(0x18),
    monotonicMillis: clock,
    ...overrides
  }
}

async function temporaryRoot (t, name = 'blind-replay-journal-v2-') {
  await fs.mkdir(SCRATCH_ROOT, { recursive: true, mode: 0o700 })
  await fs.chmod(SCRATCH_ROOT, 0o700)
  const created = await fs.mkdtemp(path.join(SCRATCH_ROOT, name))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
    return null
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

function throwsCode (t, callback, code) {
  try {
    callback()
    t.fail(`expected ${code}`)
    return null
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

async function closeQuietly (authority) {
  if (authority) await closePrivateIpcReplayJournalV2(authority).catch(() => {})
}

function tuple (value) {
  const output = b4a.alloc(32)
  output.writeUInt32BE(value, 28)
  return output
}

async function flipByte (file, offset) {
  const handle = await fs.open(file, 'r+')
  try {
    const value = b4a.alloc(1)
    const read = await handle.read(value, 0, 1, offset)
    if (read.bytesRead !== 1) throw new Error('test corruption offset is outside file')
    value[0] ^= 1
    await handle.write(value, 0, 1, offset)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

test('V2 replay timing policy is frozen, explicit, and machine-pinned', t => {
  t.ok(Object.isFrozen(PRIVATE_IPC_V2_REPLAY_POLICY))
  t.alike(PRIVATE_IPC_V2_REPLAY_POLICY, {
    capacity: 4096,
    acceptedRecordMaximumTtlMillis: 15_000,
    freshEntryExpiry: 'exact-open-deadline',
    recoveredEntryMinimumRetentionMillis: 15_000,
    recoveredRetentionBasis: 'conservative-startup-fence-not-accepted-record-ttl',
    startupWriteQuarantineMillis: 15_000,
    quarantineReadyAck: 'suppress-or-refuse',
    quarantineReadinessBrand: 'withheld',
    quarantineZeroWriteBitsAckPermitted: false,
    liveEntryEvictionPermitted: false,
    authorityKind: 'module-private-branded-journal-and-one-use-consume-receipt'
  })
  for (const field of [
    'acceptedRecordMaximumTtlMillis',
    'recoveredEntryMinimumRetentionMillis',
    'startupWriteQuarantineMillis'
  ]) {
    t.is(PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS[field],
      PRIVATE_IPC_V2_REPLAY_POLICY[field])
    t.is(PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS[field],
      PRIVATE_IPC_V2_REPLAY_POLICY[field])
  }
})

test('V2 replay journal bootstraps one exact private format and exposes only opaque capabilities', async t => {
  const root = await temporaryRoot(t)
  let now = 1_000n
  const partitionKey = fixed(0x18)
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, { partitionKey }))
  t.teardown(() => closeQuietly(authority))

  t.alike(Object.keys(authority), [])
  t.ok(Object.isFrozen(authority))
  t.alike(partitionKey, fixed(0x18), 'caller-owned partition material is not retained or zeroed')
  t.alike((await fs.readdir(root)).sort(), [JOURNAL_FILE, LOCK_FILE])

  const journalPath = path.join(root, JOURNAL_FILE)
  const lockPath = path.join(root, LOCK_FILE)
  const journalStat = await fs.lstat(journalPath)
  const lockStat = await fs.lstat(lockPath)
  t.is(journalStat.mode & 0o777, 0o600)
  t.is(lockStat.mode & 0o777, 0o600)
  t.is(journalStat.nlink, 1)
  t.is(lockStat.nlink, 1)
  t.is(journalStat.size, PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.headerBytes)

  const header = await fs.readFile(journalPath)
  t.is(header.subarray(0, 8).toString('ascii'), 'HRRPJ002')
  t.is(header.readUInt16BE(8), 2)
  t.is(header.readUInt16BE(10), 320)
  t.is(header.readUInt16BE(12), 160)
  t.is(header.readUInt16BE(14), 4096)
  t.is(header.readUInt32BE(16), PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis)
  t.is(header.readBigUInt64BE(20), 1n)

  const status = privateIpcReplayJournalV2Status(authority)
  t.is(status.ready, false)
  t.is(status.reason, 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')
  t.is(status.capacity, 4096)
  t.is(status.acceptedRecordMaximumTtlMillis,
    PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis)
  t.is(status.recoveredEntryMinimumRetentionMillis,
    PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis)
  t.is(status.startupWriteQuarantineMillis,
    PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis)
  t.is(PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS.releaseReady, false)
  t.is(PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS.serverWired, false)
  t.is(PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS.restartPolicy,
    'MANDATORY_FULL_HORIZON_STARTUP_QUARANTINE')

  t.exception(() => privateIpcReplayJournalV2Status(Object.freeze({})), /forged or unsupported/)
  await closePrivateIpcReplayJournalV2(authority)
  t.is(privateIpcReplayJournalV2Status(authority).state, 'CLOSED')
  now++
})

test('V2 replay receipts are empty one-use brands and consumption leaks no replay data', async t => {
  const root = await temporaryRoot(t)
  let now = 2_000n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const mutable = tuple(1)
  const expected = b4a.from(mutable)
  const reserving = reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: mutable,
    expiresMonotonicMillis: now + 100n
  })
  mutable.fill(0xff)
  const receipt = await reserving
  t.alike(Object.keys(receipt), [])
  t.ok(Object.isFrozen(receipt))
  t.is(receipt.kind, undefined)
  t.is(receipt.replayTupleHash, undefined)

  const consumed = consumePrivateIpcReplayReservationV2(authority, receipt, {
    replayTupleHash: expected,
    expiresMonotonicMillis: now + 100n
  })
  t.is(consumed, true)
  t.is(typeof consumed, 'boolean')
  await rejectsCode(t, Promise.resolve().then(() => consumePrivateIpcReplayReservationV2(authority, receipt, {
    replayTupleHash: expected,
    expiresMonotonicMillis: now + 100n
  })), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  await rejectsCode(t, Promise.resolve().then(() => consumePrivateIpcReplayReservationV2(authority,
    Object.freeze({}), {
      replayTupleHash: expected,
      expiresMonotonicMillis: now + 100n
    })), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
})

test('V2 replay reserve never mints a receipt after slow fsync crosses expiry', async t => {
  const root = await temporaryRoot(t, 'blind-replay-slow-fsync-v2-')
  let now = 2_100n
  let expireAfterSync = false
  let crossed = false
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
    faultInjector: async point => {
      if (expireAfterSync && point === 'reserve:after-sync') {
        expireAfterSync = false
        crossed = true
        now++
      }
    }
  }))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const replayTupleHash = tuple(101)
  expireAfterSync = true
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: now + 1n
  }), 'PRIVATE_IPC_V2_EXPIRED')
  t.is(crossed, true)
  t.is(privateIpcReplayJournalV2Status(authority).recordCount, 1)

  const replacementExpiry = now + 100n
  const replacement = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: replacementExpiry
  })
  t.is(privateIpcReplayJournalV2Status(authority).recordCount, 3)
  t.is(consumePrivateIpcReplayReservationV2(authority, replacement, {
    replayTupleHash,
    expiresMonotonicMillis: replacementExpiry
  }), true)
})

test('V2 replay receipt held through expiry and same-tuple reuse is stale', async t => {
  const root = await temporaryRoot(t, 'blind-replay-reuse-receipt-v2-')
  let now = 2_200n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const replayTupleHash = tuple(102)
  const oldExpiry = now + 1n
  const oldReceipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: oldExpiry
  })
  now = oldExpiry
  const currentExpiry = now + 100n
  const currentReceipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: currentExpiry
  })

  throwsCode(t, () => consumePrivateIpcReplayReservationV2(authority, oldReceipt, {
    replayTupleHash,
    expiresMonotonicMillis: oldExpiry
  }), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  t.is(consumePrivateIpcReplayReservationV2(authority, currentReceipt, {
    replayTupleHash,
    expiresMonotonicMillis: currentExpiry
  }), true)
})

test('V2 replay compaction invalidates receipts for rewritten live entries', async t => {
  const root = await temporaryRoot(t, 'blind-replay-compact-receipt-v2-')
  let now = 2_300n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
    compactionRecordLimit: 2
  }))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const retainedTuple = tuple(103)
  const retainedExpiry = now + 500n
  const staleReceipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: retainedTuple,
    expiresMonotonicMillis: retainedExpiry
  })
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(104),
    expiresMonotonicMillis: now + 1n
  })
  now++
  const currentTuple = tuple(105)
  const currentExpiry = now + 500n
  const currentReceipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: currentTuple,
    expiresMonotonicMillis: currentExpiry
  })
  t.is(privateIpcReplayJournalV2Status(authority).generation, 2n)

  throwsCode(t, () => consumePrivateIpcReplayReservationV2(authority, staleReceipt, {
    replayTupleHash: retainedTuple,
    expiresMonotonicMillis: retainedExpiry
  }), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  t.is(consumePrivateIpcReplayReservationV2(authority, currentReceipt, {
    replayTupleHash: currentTuple,
    expiresMonotonicMillis: currentExpiry
  }), true)
})

test('V2 replay wrong binding burns an otherwise valid one-use receipt', async t => {
  const root = await temporaryRoot(t, 'blind-replay-wrong-binding-v2-')
  let now = 2_400n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const replayTupleHash = tuple(106)
  const expiry = now + 100n
  const receipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: expiry
  })
  throwsCode(t, () => consumePrivateIpcReplayReservationV2(authority, receipt, {
    replayTupleHash: tuple(107),
    expiresMonotonicMillis: expiry
  }), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  throwsCode(t, () => consumePrivateIpcReplayReservationV2(authority, receipt, {
    replayTupleHash,
    expiresMonotonicMillis: expiry
  }), 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
})

test('V2 replay recursive getter and Proxy permit exactly one receipt success', async t => {
  const root = await temporaryRoot(t, 'blind-replay-recursive-binding-v2-')
  let now = 2_500n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const replayTupleHash = tuple(108)
  const expiry = now + 100n
  const receipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: expiry
  })
  const exactBinding = { replayTupleHash, expiresMonotonicMillis: expiry }
  let reentered = false
  let recursiveResult = null
  let recursiveError = null
  let outerResult = null
  let getterCount = 0
  let ownKeysCount = 0
  let getTrapCount = 0
  const target = {
    get replayTupleHash () {
      getterCount++
      if (!reentered) {
        reentered = true
        try {
          recursiveResult = consumePrivateIpcReplayReservationV2(authority, receipt, exactBinding)
        } catch (error) {
          recursiveError = error
        }
      }
      return replayTupleHash
    },
    get expiresMonotonicMillis () {
      getterCount++
      return expiry
    }
  }
  const bindingProxy = new Proxy(target, {
    ownKeys (value) {
      ownKeysCount++
      return Reflect.ownKeys(value)
    },
    get (value, key, receiver) {
      getTrapCount++
      return Reflect.get(value, key, receiver)
    }
  })

  throwsCode(t, () => {
    outerResult = consumePrivateIpcReplayReservationV2(authority, receipt, bindingProxy)
  }, 'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  t.is(recursiveResult, true)
  t.is(recursiveError, null)
  t.is(Number(recursiveResult === true) + Number(outerResult === true), 1)
  t.is(ownKeysCount, 1)
  t.is(getTrapCount, 2)
  t.is(getterCount, 2)
})

test('V2 replay reservation is exact, concurrent, bounded by expiry and durable before late cancellation', async t => {
  const root = await temporaryRoot(t)
  let now = 3_000n
  const lateAbort = new AbortController()
  let abortAfterWrite = false
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
    faultInjector: async point => {
      if (abortAfterWrite && point === 'reserve:after-write') lateAbort.abort()
    }
  }))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  const replayTupleHash = tuple(2)
  const results = await Promise.allSettled(Array.from({ length: 16 }, () =>
    reservePrivateIpcReplayTupleV2(authority, {
      replayTupleHash,
      expiresMonotonicMillis: now + 50n
    })))
  t.is(results.filter(result => result.status === 'fulfilled').length, 1)
  t.is(results.filter(result => result.status === 'rejected' &&
    result.reason.code === 'PRIVATE_IPC_V2_REPLAY').length, 15)
  t.is(privateIpcReplayJournalV2Status(authority).occupied, 1)

  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(3),
    expiresMonotonicMillis: now
  }), 'PRIVATE_IPC_V2_EXPIRED')
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(3),
    expiresMonotonicMillis: now + 15_001n
  }), 'PRIVATE_IPC_V2_EXPIRED')

  now += 50n
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: now + 50n
  })
  t.is(privateIpcReplayJournalV2Status(authority).recordCount, 3,
    'durable EXPIRE precedes reuse of an exact tuple')

  const preAborted = new AbortController()
  preAborted.abort()
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(4),
    expiresMonotonicMillis: now + 50n,
    signal: preAborted.signal
  }), 'ABORT_ERR')
  const beforeLate = privateIpcReplayJournalV2Status(authority).recordCount
  abortAfterWrite = true
  const lateReceipt = await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(5),
    expiresMonotonicMillis: now + 50n,
    signal: lateAbort.signal
  })
  t.ok(Object.isFrozen(lateReceipt))
  t.is(lateAbort.signal.aborted, true)
  t.is(privateIpcReplayJournalV2Status(authority).recordCount, beforeLate + 1,
    'cancellation after the first journal write cannot interrupt fsync')
})

test('V2 replay journal enforces exact 4096 live capacity without eviction', async t => {
  const root = await temporaryRoot(t, 'blind-replay-capacity-v2-')
  let now = 4_000n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n

  for (let index = 1; index <= PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.capacity; index++) {
    await reservePrivateIpcReplayTupleV2(authority, {
      replayTupleHash: tuple(index),
      expiresMonotonicMillis: now + 15_000n
    })
  }
  const full = privateIpcReplayJournalV2Status(authority)
  t.is(full.occupied, 4096)
  t.is(full.recordCount, 4096)
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(4097),
    expiresMonotonicMillis: now + 15_000n
  }), 'BLIND_STREAM_BUSY')
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(1),
    expiresMonotonicMillis: now + 15_000n
  }), 'PRIVATE_IPC_V2_REPLAY')
  t.is(privateIpcReplayJournalV2Status(authority).occupied, 4096)
  t.is((await fs.lstat(path.join(root, JOURNAL_FILE))).size,
    PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.headerBytes +
    (4096 * PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.frameBytes))
})

test('V2 replay restart applies global quarantine and conservatively retains every recovered tuple', async t => {
  const root = await temporaryRoot(t, 'blind-replay-restart-v2-')
  let now = 5_000n
  const options = () => journalOptions(root, () => now)
  let authority = await openPrivateIpcReplayJournalV2(options())
  t.teardown(() => closeQuietly(authority))
  now += 15_000n
  const replayTupleHash = tuple(11)
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: now + 1n
  })
  await closePrivateIpcReplayJournalV2(authority)

  authority = await openPrivateIpcReplayJournalV2(options())
  let status = privateIpcReplayJournalV2Status(authority)
  t.is(status.ready, false)
  t.is(status.occupied, 1)
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(12),
    expiresMonotonicMillis: now + 100n
  }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')

  now += 15_000n
  status = privateIpcReplayJournalV2Status(authority)
  t.is(status.ready, true)
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash,
    expiresMonotonicMillis: now + 100n
  })
  t.is(privateIpcReplayJournalV2Status(authority).occupied, 1)
  await closePrivateIpcReplayJournalV2(authority)

  authority = await openPrivateIpcReplayJournalV2(options())
  t.is(privateIpcReplayJournalV2Status(authority).occupied, 1)
  t.is(privateIpcReplayJournalV2Status(authority).ready, false,
    'every restart extends the full conservative horizon')
})

test('V2 replay recovery truncates only a partial tail and rejects a complete corrupt frame', async t => {
  const partialRoot = await temporaryRoot(t, 'blind-replay-partial-v2-')
  let now = 6_000n
  let authority = await openPrivateIpcReplayJournalV2(journalOptions(partialRoot, () => now))
  now += 15_000n
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(21),
    expiresMonotonicMillis: now + 100n
  })
  await closePrivateIpcReplayJournalV2(authority)
  const partialPath = path.join(partialRoot, JOURNAL_FILE)
  await fs.appendFile(partialPath, b4a.alloc(37, 0xa5))
  authority = await openPrivateIpcReplayJournalV2(journalOptions(partialRoot, () => now))
  t.is((await fs.lstat(partialPath)).size,
    PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.headerBytes + PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.frameBytes)
  t.is(privateIpcReplayJournalV2Status(authority).occupied, 1)
  await closePrivateIpcReplayJournalV2(authority)

  const corruptRoot = await temporaryRoot(t, 'blind-replay-corrupt-v2-')
  authority = await openPrivateIpcReplayJournalV2(journalOptions(corruptRoot, () => now))
  now += 15_000n
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(22),
    expiresMonotonicMillis: now + 100n
  })
  await closePrivateIpcReplayJournalV2(authority)
  await flipByte(path.join(corruptRoot, JOURNAL_FILE),
    PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.headerBytes + 100)
  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(corruptRoot, () => now)),
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
})

test('V2 replay journal binds exact durability identity and rejects unsafe files and competing writers', async t => {
  const root = await temporaryRoot(t, 'blind-replay-files-v2-')
  let now = 7_000n
  let authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  const competing = await fs.open(path.join(root, LOCK_FILE), 'r+')
  t.is(tryExclusiveFileLock(competing), false)
  await competing.close()
  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(root, () => now)),
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_LOCKED')
  await closePrivateIpcReplayJournalV2(authority)

  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
    storeId: fixed(0x99)
  })), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_IDENTITY_MISMATCH')

  await fs.chmod(path.join(root, JOURNAL_FILE), 0o644)
  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(root, () => now)),
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  await fs.chmod(path.join(root, JOURNAL_FILE), 0o600)
  const hardlink = path.join(root, 'hardlink-test')
  await fs.link(path.join(root, JOURNAL_FILE), hardlink)
  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(root, () => now)),
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  await fs.unlink(hardlink)

  const badModeRoot = await temporaryRoot(t, 'blind-replay-mode-v2-')
  await fs.chmod(badModeRoot, 0o755)
  await rejectsCode(t, openPrivateIpcReplayJournalV2(journalOptions(badModeRoot, () => now)),
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  await fs.chmod(badModeRoot, 0o700)

  authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  now += 15_000n
  const displaced = path.join(root, 'writer.lock.displaced')
  await fs.rename(path.join(root, LOCK_FILE), displaced)
  await fs.writeFile(path.join(root, LOCK_FILE), b4a.alloc(0), { mode: 0o600 })
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(31),
    expiresMonotonicMillis: now + 100n
  }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  t.is(privateIpcReplayJournalV2Status(authority).state, 'POISONED')
  await closePrivateIpcReplayJournalV2(authority)

  const lock = await fs.open(path.join(root, LOCK_FILE), 'r+')
  t.is(tryExclusiveFileLock(lock), true)
  releaseExclusiveFileLock(lock)
  await lock.close()
})

test('V2 replay journal poisons on post-fsync uncertainty and recovers the durable consume', async t => {
  const root = await temporaryRoot(t, 'blind-replay-poison-v2-')
  let now = 8_000n
  let injected = false
  let authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
    faultInjector: async point => {
      if (!injected && point === 'reserve:after-sync') {
        injected = true
        const error = new Error('injected post-fsync response loss')
        error.code = 'INJECTED_POST_FSYNC'
        throw error
      }
    }
  }))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(41),
    expiresMonotonicMillis: now + 100n
  }), 'INJECTED_POST_FSYNC')
  let status = privateIpcReplayJournalV2Status(authority)
  t.is(status.state, 'POISONED')
  t.is(status.reason, 'INJECTED_POST_FSYNC')
  await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(42),
    expiresMonotonicMillis: now + 100n
  }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_POISONED')
  await closePrivateIpcReplayJournalV2(authority)

  authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  status = privateIpcReplayJournalV2Status(authority)
  t.is(status.occupied, 1, 'a record fsynced before response loss remains consumed after restart')
  t.is(status.ready, false)
})

test('V2 replay post-fsync acceptance revalidates the exact root, lock, and journal paths', async t => {
  for (const [displacedBinding, initialNow, tupleByte] of [
    ['lock', 8_100n, 43],
    ['journal', 8_200n, 44],
    ['root', 8_300n, 45]
  ]) {
    const root = await temporaryRoot(t, `blind-replay-post-sync-${displacedBinding}-v2-`)
    const displaced = displacedBinding === 'root'
      ? `${root}.post-sync-displaced`
      : path.join(root, displacedBinding === 'lock'
        ? 'writer.lock.post-sync-displaced'
        : 'replay-journal.post-sync-displaced')
    t.teardown(() => fs.rm(displaced, { recursive: true, force: true }))
    let now = initialNow
    let injected = false
    let authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
      faultInjector: async point => {
        if (injected || point !== 'reserve:after-sync') return
        injected = true
        if (displacedBinding === 'lock') {
          await fs.rename(path.join(root, LOCK_FILE), displaced)
          await fs.writeFile(path.join(root, LOCK_FILE), b4a.alloc(0), { mode: 0o600 })
        } else if (displacedBinding === 'journal') {
          await fs.rename(path.join(root, JOURNAL_FILE), displaced)
          await fs.writeFile(path.join(root, JOURNAL_FILE), b4a.alloc(0), { mode: 0o600 })
        } else {
          await fs.rename(root, displaced)
          await fs.mkdir(root, { mode: 0o700 })
          await fs.chmod(root, 0o700)
        }
      }
    }))
    t.teardown(() => closeQuietly(authority))
    now += BigInt(PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis)

    await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
      replayTupleHash: tuple(tupleByte),
      expiresMonotonicMillis: now + 100n
    }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
    t.is(injected, true, `${displacedBinding} displacement fault was exercised after fsync`)
    t.is(privateIpcReplayJournalV2Status(authority).state, 'POISONED')
    await closePrivateIpcReplayJournalV2(authority)

    if (displacedBinding === 'lock') {
      await fs.unlink(path.join(root, LOCK_FILE))
      await fs.rename(displaced, path.join(root, LOCK_FILE))
    } else if (displacedBinding === 'journal') {
      await fs.unlink(path.join(root, JOURNAL_FILE))
      await fs.rename(displaced, path.join(root, JOURNAL_FILE))
    } else {
      await fs.rm(root, { recursive: true, force: true })
      await fs.rename(displaced, root)
    }

    authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
    const recovered = privateIpcReplayJournalV2Status(authority)
    t.is(recovered.occupied, 1,
      `${displacedBinding} displacement did not erase the fsynced conservative consume`)
    t.is(recovered.ready, false)
    await closePrivateIpcReplayJournalV2(authority)
  }
})

test('V2 replay compaction installs one bounded live snapshot and survives every publication fault point', async t => {
  const successRoot = await temporaryRoot(t, 'blind-replay-compact-v2-')
  let now = 9_000n
  let authority = await openPrivateIpcReplayJournalV2(journalOptions(successRoot, () => now, {
    compactionRecordLimit: 2
  }))
  now += 15_000n
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(51),
    expiresMonotonicMillis: now + 1n
  })
  now++
  await reservePrivateIpcReplayTupleV2(authority, {
    replayTupleHash: tuple(52),
    expiresMonotonicMillis: now + 100n
  })
  const compacted = privateIpcReplayJournalV2Status(authority)
  t.is(compacted.generation, 2n)
  t.is(compacted.recordCount, 1)
  t.is(compacted.occupied, 1)
  t.is((await fs.lstat(path.join(successRoot, JOURNAL_FILE))).size,
    PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.headerBytes + PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS.frameBytes)
  await closePrivateIpcReplayJournalV2(authority)

  for (const [point, expectedGeneration, expectedOccupied] of [
    ['compaction:after-temp-write', 1n, 1],
    ['compaction:after-temp-sync', 1n, 1],
    ['compaction:after-rename', 2n, 0],
    ['compaction:after-directory-sync', 2n, 0]
  ]) {
    const root = await temporaryRoot(t, `blind-replay-${point.split(':').at(-1)}-v2-`)
    now += 100_000n
    let fired = false
    authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
      compactionRecordLimit: 2,
      faultInjector: async observed => {
        if (!fired && observed === point) {
          fired = true
          const error = new Error(`injected ${point}`)
          error.code = 'INJECTED_COMPACTION_FAULT'
          throw error
        }
      }
    }))
    now += 15_000n
    await reservePrivateIpcReplayTupleV2(authority, {
      replayTupleHash: tuple(61),
      expiresMonotonicMillis: now + 1n
    })
    now++
    await rejectsCode(t, reservePrivateIpcReplayTupleV2(authority, {
      replayTupleHash: tuple(62),
      expiresMonotonicMillis: now + 100n
    }), 'INJECTED_COMPACTION_FAULT')
    t.is(fired, true, `${point} was exercised`)
    t.is(privateIpcReplayJournalV2Status(authority).state, 'POISONED')
    await closePrivateIpcReplayJournalV2(authority)

    authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now, {
      compactionRecordLimit: 2
    }))
    const recovered = privateIpcReplayJournalV2Status(authority)
    t.is(recovered.generation, expectedGeneration,
      `${point} recovers the generation selected by the rename boundary`)
    t.is(recovered.occupied, expectedOccupied,
      `${point} recovers the exact live set selected by the rename boundary`)
    t.is(recovered.recordCount, expectedOccupied,
      `${point} recovers the exact compacted record count`)
    t.is(recovered.ready, false)
    await closePrivateIpcReplayJournalV2(authority)
  }
})

test('V2 replay journal poisons on monotonic regression without mutating its durable log', async t => {
  const root = await temporaryRoot(t, 'blind-replay-clock-v2-')
  let now = 10_000n
  const authority = await openPrivateIpcReplayJournalV2(journalOptions(root, () => now))
  t.teardown(() => closeQuietly(authority))
  now += 15_000n
  t.is(privateIpcReplayJournalV2Status(authority).ready, true)
  const before = (await fs.lstat(path.join(root, JOURNAL_FILE))).size
  now--
  const status = privateIpcReplayJournalV2Status(authority)
  t.is(status.state, 'POISONED')
  t.is(status.reason, 'PRIVATE_IPC_V2_REPLAY_JOURNAL_CLOCK_UNSAFE')
  t.is((await fs.lstat(path.join(root, JOURNAL_FILE))).size, before)
})
