import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  BlindStoreSession,
  acquireBlindStoreSessionTransactionLease
} from '../store-session.js'
import { BlindTransactionStore } from '../transaction-store.js'
import {
  scanBlindWalV2ForAnchoredRecovery,
  verifyBlindWalRecoveryScanResult
} from '../wal-recovery-scan.js'

const MAP_GENERATION = 7n
const WRITER_FENCE = b4a.alloc(32, 0x72)
const CONTINUITY = b4a.alloc(32, 0x73)

async function temporaryRoot (t, name) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), name))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function walFixture (t, count, name = 'hiverelay-wal-recovery-') {
  const root = await temporaryRoot(t, name)
  const store = new BlindTransactionStore({
    root,
    partitionKey: b4a.alloc(32, 0x71),
    mapGeneration: MAP_GENERATION,
    ownerFenceTokenHash: WRITER_FENCE,
    durabilityContinuityHash: CONTINUITY
  })
  await store.open(async () => {})
  const frames = []
  for (let index = 1; index <= count; index++) {
    frames.push(await store.append({
      type: index,
      transactionId: b4a.alloc(32, index),
      virtualBucket: index,
      payload: b4a.alloc(index * 3, 0x80 + index)
    }))
  }
  await store.close()
  const control = path.join(root, 'control')
  const walPath = path.join(control, 'wal.v2')
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x74), { mode: 0o600 })
  return { root, control, walPath, frames }
}

async function lockedFixture (t, count, name) {
  const fixture = await walFixture(t, count, name)
  const session = new BlindStoreSession({ root: fixture.root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), fixture.root)
  t.teardown(async () => {
    lease.release()
    await session.close()
  })
  return { ...fixture, session, lease }
}

function scanOptions (fixture, checkpoint, applyShadowFrame, overrides = {}) {
  return {
    root: fixture.root,
    lease: fixture.lease,
    checkpoint: {
      sequence: checkpoint.sequence,
      hash: checkpoint.walHash
    },
    mapGeneration: MAP_GENERATION,
    writerFenceTokenHash: WRITER_FENCE,
    durabilityContinuityHash: CONTINUITY,
    maximumWalBytes: 1024 * 1024,
    maximumWalFrames: 1024,
    maximumWalPayloadBytes: 1024 * 1024,
    applyShadowFrame,
    ...overrides
  }
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

function frameStart (frames, index) {
  let offset = 0
  for (let cursor = 0; cursor < index; cursor++) offset += frames[cursor].frameBytes
  return offset
}

test('anchored scan validates the full prefix and awaits only post-checkpoint shadow replay', async t => {
  const fixture = await lockedFixture(t, 4, 'hiverelay-wal-recovery-complete-')
  const before = await fs.readFile(fixture.walPath)
  const replayed = []
  let applying = false
  const result = await scanBlindWalV2ForAnchoredRecovery(scanOptions(fixture, fixture.frames[1], async frame => {
    t.is(applying, false)
    applying = true
    await Promise.resolve()
    replayed.push({ sequence: frame.sequence, payload: b4a.from(frame.payload), offset: frame.walOffset })
    frame.payload.fill(0)
    applying = false
  }))

  t.alike(replayed.map(frame => frame.sequence), [3n, 4n])
  t.alike(replayed.map(frame => frame.offset), [frameStart(fixture.frames, 2), frameStart(fixture.frames, 3)])
  t.alike(replayed.map(frame => frame.payload[0]), [0x83, 0x84])
  t.is(result.checkpointSequence, 2n)
  t.alike(result.checkpointHash, fixture.frames[1].walHash)
  t.is(result.checkpointEndOffset, frameStart(fixture.frames, 2))
  t.is(result.headSequence, 4n)
  t.alike(result.headHash, fixture.frames[3].walHash)
  t.is(result.headEndOffset, before.byteLength)
  t.is(result.observedWalBytes, before.byteLength)
  t.is(result.completeFrameCount, 4)
  t.is(result.replayedFrameCount, 2)
  t.is(result.tornTailOffset, null)
  t.is(result.tornTailBytes, 0)
  t.is(await verifyBlindWalRecoveryScanResult(result, fixture.root, fixture.lease), true)
  const exposed = result.headHash
  exposed.fill(0)
  t.is(await verifyBlindWalRecoveryScanResult(result, fixture.root, fixture.lease), true)
  await rejectsCode(t,
    verifyBlindWalRecoveryScanResult(Object.freeze({ ...result }), fixture.root, fixture.lease),
    'BLIND_WAL_RECOVERY_RESULT_INVALID')
  t.alike(await fs.readFile(fixture.walPath), before)
})

test('final partial header and final partial body are reported without truncation', async t => {
  for (const [name, partialBytes] of [
    ['header', 91],
    ['body', 197]
  ]) {
    const fixture = await lockedFixture(t, 4, `hiverelay-wal-recovery-torn-${name}-`)
    const tornOffset = frameStart(fixture.frames, 3)
    fixture.lease.release()
    await fixture.session.close()
    await fs.truncate(fixture.walPath, tornOffset + partialBytes)

    const session = new BlindStoreSession({ root: fixture.root })
    await session.open()
    const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), fixture.root)
    const active = { ...fixture, session, lease }
    const before = await fs.readFile(active.walPath)
    const replayed = []
    const result = await scanBlindWalV2ForAnchoredRecovery(scanOptions(active, active.frames[1], async frame => {
      replayed.push(frame.sequence)
    }))
    t.alike(replayed, [3n], `${name} tail replays only the complete frame after the checkpoint`)
    t.is(result.headSequence, 3n, `${name} tail preserves the last complete head`)
    t.is(result.tornTailOffset, tornOffset, `${name} tail offset`)
    t.is(result.tornTailBytes, partialBytes, `${name} tail byte count`)
    t.alike(await fs.readFile(active.walPath), before, `${name} tail remains byte-exact`)
    lease.release()
    await session.close()
  }
})

test('a torn frame cannot satisfy the checkpoint anchor', async t => {
  const fixture = await walFixture(t, 4, 'hiverelay-wal-recovery-torn-anchor-')
  const tornOffset = frameStart(fixture.frames, 3)
  await fs.truncate(fixture.walPath, tornOffset + 80)
  const session = new BlindStoreSession({ root: fixture.root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), fixture.root)
  const active = { ...fixture, session, lease }
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(active, active.frames[3], async () => {})),
    /exact complete checkpoint anchor/)
  lease.release()
  await session.close()
})

test('interior corruption, wrong authority, and scan bounds fail closed', async t => {
  const corrupted = await walFixture(t, 4, 'hiverelay-wal-recovery-corrupt-')
  const bytes = await fs.readFile(corrupted.walPath)
  bytes[frameStart(corrupted.frames, 2) + 192] ^= 1
  await fs.writeFile(corrupted.walPath, bytes)
  const corruptedSession = new BlindStoreSession({ root: corrupted.root })
  await corruptedSession.open()
  const corruptedLease = await acquireBlindStoreSessionTransactionLease(corruptedSession.lockContext(), corrupted.root)
  const corruptedActive = { ...corrupted, session: corruptedSession, lease: corruptedLease }
  let replayed = 0
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    corruptedActive,
    corruptedActive.frames[1],
    async () => { replayed++ }
  )), /payload hash/)
  t.is(replayed, 0)
  corruptedLease.release()
  await corruptedSession.close()

  const bounded = await lockedFixture(t, 4, 'hiverelay-wal-recovery-bounds-')
  const walBytes = (await fs.stat(bounded.walPath)).size
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    bounded.frames[0],
    async () => {},
    { maximumWalBytes: walBytes - 1 }
  )), /maximumWalBytes/)
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    bounded.frames[0],
    async () => {},
    { maximumWalFrames: 2 }
  )), /maximumWalFrames/)
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    bounded.frames[0],
    async () => {},
    { mapGeneration: MAP_GENERATION + 1n }
  )), /bucket-map generation/)
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    bounded.frames[0],
    async () => {},
    { writerFenceTokenHash: b4a.alloc(32, 0x75) }
  )), /writer fence/)
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    bounded.frames[0],
    async () => {},
    { durabilityContinuityHash: b4a.alloc(32, 0x76) }
  )), /durability continuity/)
  const wrongHash = b4a.from(bounded.frames[0].walHash)
  wrongHash[0] ^= 1
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    bounded,
    { ...bounded.frames[0], walHash: wrongHash },
    async () => {}
  )), /checkpoint hash/)
})

test('sequence gaps and checksum-only corruption are never classified as torn tails', async t => {
  const gap = await walFixture(t, 3, 'hiverelay-wal-recovery-gap-')
  const gapBytes = await fs.readFile(gap.walPath)
  gapBytes[frameStart(gap.frames, 1) + 17] = 3
  await fs.writeFile(gap.walPath, gapBytes)
  const gapSession = new BlindStoreSession({ root: gap.root })
  await gapSession.open()
  const gapLease = await acquireBlindStoreSessionTransactionLease(gapSession.lockContext(), gap.root)
  const gapActive = { ...gap, session: gapSession, lease: gapLease }
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    gapActive,
    gapActive.frames[0],
    async () => {}
  )), /sequence gap or fork/)
  gapLease.release()
  await gapSession.close()

  const checksum = await walFixture(t, 3, 'hiverelay-wal-recovery-checksum-')
  const checksumBytes = await fs.readFile(checksum.walPath)
  checksumBytes[checksumBytes.byteLength - 1] ^= 1
  await fs.writeFile(checksum.walPath, checksumBytes)
  const checksumSession = new BlindStoreSession({ root: checksum.root })
  await checksumSession.open()
  const checksumLease = await acquireBlindStoreSessionTransactionLease(checksumSession.lockContext(), checksum.root)
  const checksumActive = { ...checksum, session: checksumSession, lease: checksumLease }
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    checksumActive,
    checksumActive.frames[1],
    async () => {}
  )), /checksum mismatch/)
  checksumLease.release()
  await checksumSession.close()
})

test('callback failure, unsafe inode, and expired lease produce no reusable result', async t => {
  const callbackFixture = await lockedFixture(t, 3, 'hiverelay-wal-recovery-callback-')
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    callbackFixture,
    callbackFixture.frames[0],
    async () => { throw new Error('shadow reconstruction refused frame') }
  )), /shadow reconstruction refused frame/)

  const linked = await lockedFixture(t, 2, 'hiverelay-wal-recovery-link-')
  await fs.link(linked.walPath, path.join(linked.root, 'wal-hardlink'))
  await t.exception(scanBlindWalV2ForAnchoredRecovery(scanOptions(
    linked,
    linked.frames[0],
    async () => {}
  )), /single-link regular file/)

  const expiry = await lockedFixture(t, 2, 'hiverelay-wal-recovery-expiry-')
  const result = await scanBlindWalV2ForAnchoredRecovery(scanOptions(expiry, expiry.frames[0], async () => {}))
  expiry.lease.release()
  await rejectsCode(t,
    verifyBlindWalRecoveryScanResult(result, expiry.root, expiry.lease),
    'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  await expiry.session.close()
})
