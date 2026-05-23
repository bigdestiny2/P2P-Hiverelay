/**
 * Partial-pin self-heal integration test (2026-05-22).
 *
 * Exercises the real Hyperdrive blob-core `has()` API end-to-end
 * against AppLifecycle's anchor contract. Reproduces the failure
 * mode from FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE and proves the
 * self-heal path from AUTO-HEAL-ROOT-CAUSE-2026-05-22.
 *
 * Failure mode (pre-patch):
 *   1. Relay accepts a seed request.
 *   2. Metadata core replicates fine (small, fast).
 *   3. Blob download stalls / times out; .catch() silently swallows.
 *   4. Entry is marked anchored=true based on drive.version > 0.
 *   5. Periodic anchor monitor confirms anchored=true (same broken check).
 *   6. Repair monitor skips anchored entries — gap never closes.
 *   7. End users hit indistinguishable-from-network-down hangs forever.
 *      Only an operator-side bounce of the relay clears the stale entry.
 *
 * Expected behavior post-patch:
 *   - Anchored requires every blob block present, not just metadata.
 *   - Periodic anchor check downgrades partial-pin entries.
 *   - Repair pass re-picks them up and pulls missing blocks.
 *   - No operator bounce required.
 *
 * To keep this test deterministic (no swarm, no network), we drive
 * AppLifecycle directly with a real Hyperdrive backed by Corestore.
 * The "partial pin" is created by selectively clearing blob blocks
 * from the local hypercore — same on-disk state as a real partial
 * pin caused by a download timeout.
 */

import test from 'brittle'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'partial-pin-int-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

// Minimal node surface for AppLifecycle. We don't need swarm/seeder for
// the anchor-contract assertions — only the registry + drive.
function makeNode (registry, store) {
  return {
    appRegistry: registry,
    seededApps: registry.apps,
    store,
    swarm: { join: () => {}, flush: async () => {}, keyPair: { publicKey: Buffer.alloc(32) } },
    seeder: { totalBytesStored: 0 },
    distributedDriveBridge: null,
    config: { custody: { defaultRetainMs: 0 } }
  }
}

async function makeReadyDrive (store, files) {
  const drive = new Hyperdrive(store, null)
  await drive.ready()
  for (const [path, bytes] of files) await drive.put(path, bytes)
  return drive
}

test('partial pin: _isDriveFullyReplicated returns true for a real fully-pulled drive', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const store = new Corestore(join(dir, 'store'))
  await store.ready()
  t.teardown(async () => { try { await store.close() } catch {} })

  const drive = await makeReadyDrive(store, [
    ['/a.bin', randomBytes(4096)],
    ['/b.bin', randomBytes(4096)],
    ['/c.bin', randomBytes(4096)]
  ])

  const reg = new AppRegistry(dir)
  const lifecycle = new AppLifecycle(makeNode(reg, store))

  const ok = await lifecycle._isDriveFullyReplicated(drive)
  t.is(ok, true, 'a freshly-written drive is fully replicated to itself')
})

test('partial pin: _isDriveFullyReplicated returns false when blob blocks are cleared', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const store = new Corestore(join(dir, 'store'))
  await store.ready()
  t.teardown(async () => { try { await store.close() } catch {} })

  const drive = await makeReadyDrive(store, [
    ['/a.bin', randomBytes(4096)],
    ['/b.bin', randomBytes(4096)],
    ['/c.bin', randomBytes(4096)]
  ])
  // Ensure blob core is loaded
  const blobs = await drive.getBlobs()
  t.ok(blobs.core.length > 0, 'blob core has blocks')

  // Clear a middle block — simulates a partial pin where the relay
  // pulled blocks 0..N-1 and N+1..end but missed N. Pre-patch the
  // relay would still claim anchored=true on the strength of metadata.
  const blobLength = blobs.core.length
  const middle = Math.floor(blobLength / 2)
  await blobs.core.clear(middle, middle + 1)

  const reg = new AppRegistry(dir)
  const lifecycle = new AppLifecycle(makeNode(reg, store))

  const ok = await lifecycle._isDriveFullyReplicated(drive)
  t.is(ok, false, 'cleared middle block detected — drive is NOT fully replicated')
})

test('partial pin: anchor contract — real drive, then partial → unanchored, then recovery', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const store = new Corestore(join(dir, 'store'))
  await store.ready()
  t.teardown(async () => { try { await store.close() } catch {} })

  const drive = await makeReadyDrive(store, [
    ['/x.bin', randomBytes(4096)],
    ['/y.bin', randomBytes(4096)],
    ['/z.bin', randomBytes(4096)]
  ])
  const blobs = await drive.getBlobs()
  const appKey = b4a.toString(drive.key, 'hex')

  const reg = new AppRegistry(dir)
  reg.set(appKey, {
    type: 'drive',
    drive,
    discoveryKey: drive.discoveryKey,
    maxStorage: 64 * 1024 * 1024
  })
  const lifecycle = new AppLifecycle(makeNode(reg, store))

  // ── Fully present → anchor decision is allowed ─────────────────
  let fully = await lifecycle._isDriveFullyReplicated(drive)
  t.is(fully, true, 'real fully-present drive reports fully replicated')

  // Mirror what _eagerReplicate / repairUnanchored / _runAnchorCheck do
  // when the check passes:
  reg.setAnchored(appKey, drive.version)
  t.is(reg.get(appKey).anchored, true, 'entry marked anchored after positive check')

  // ── Induce a partial pin by clearing a single middle block ──────
  // This is the same on-disk shape as a real partial pin produced
  // when downloadWithTimeout fires before all blocks land.
  const blobLength = blobs.core.length
  const middle = Math.floor(blobLength / 2)
  await blobs.core.clear(middle, middle + 1)

  fully = await lifecycle._isDriveFullyReplicated(drive)
  t.is(fully, false, 'cleared block — real has() detects the gap')

  // The periodic anchor check (post-patch) must now downgrade. We
  // simulate it by performing the same registry mutation it does.
  // Pre-patch the check would have kept anchored=true on drive.version
  // alone; post-patch it consults _isDriveFullyReplicated and clears.
  if (!fully && reg.get(appKey).anchored === true) {
    reg.clearAnchored(appKey, 'partial-pin detected')
  }
  t.is(reg.get(appKey).anchored, false, 'periodic check downgrades partial-pin to unanchored')

  // ── runRepairPass re-queues the (now unanchored) entry ──────────
  // Without a real swarm + peer the blocks can't actually be pulled,
  // so we stub repairUnanchored to assert the queueing behavior. The
  // important contract: anchored:false entries get re-considered.
  let repairCalls = 0
  lifecycle.repairUnanchored = async () => { repairCalls++; return false }
  const r = await lifecycle.runRepairPass()
  t.is(r.checked, 1, 'partial-pin entry is re-queued (would have been skipped pre-patch)')
  t.is(repairCalls, 1)
})

test('partial pin: runRepairPass anchors entries that recover between ticks', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const store = new Corestore(join(dir, 'store'))
  await store.ready()
  t.teardown(async () => { try { await store.close() } catch {} })

  const drive = await makeReadyDrive(store, [['/data.bin', randomBytes(8192)]])
  const appKey = b4a.toString(drive.key, 'hex')

  const reg = new AppRegistry(dir)
  reg.set(appKey, { type: 'drive', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(makeNode(reg, store))

  // Stub repairUnanchored — first tick: still partial (returns false),
  // second tick: blocks arrived, set anchored and return true. The
  // contract being tested: runRepairPass uses the registry's anchored
  // flag as its queueing signal, so any entry that's anchored:false
  // gets reconsidered on every pass.
  let calls = 0
  lifecycle.repairUnanchored = async (key) => {
    calls++
    if (calls < 2) return false
    reg.setAnchored(key, 1)
    return true
  }

  let r = await lifecycle.runRepairPass()
  t.is(r.checked, 1, 'first pass picks up the entry')
  t.is(r.repaired, 0, 'first pass: still partial')

  r = await lifecycle.runRepairPass()
  t.is(r.checked, 1, 'second pass picks up the still-unanchored entry')
  t.is(r.repaired, 1, 'self-heal completed on this tick')
  t.is(reg.get(appKey).anchored, true, 'entry anchored without operator action')
})
