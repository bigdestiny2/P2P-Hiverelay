import test from 'brittle'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'repair-test-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

// Minimal mock of RelayNode for AppLifecycle's repair primitive
function mockNode (registry, opts = {}) {
  return {
    appRegistry: registry,
    swarm: opts.swarm || {
      join: () => {},
      flush: () => Promise.resolve()
    },
    seeder: opts.seeder || null,
    distributedDriveBridge: null,
    seededApps: registry?.apps || new Map(),
    config: opts.config || {}
  }
}

// Mock drive that simulates the Hyperdrive surface AppLifecycle uses.
//
// blobsComplete: drives `_isDriveFullyReplicated`. When false, the
// drive's blob core reports length > 0 but `has(0, length)` returns
// false — simulating the partial-pin failure mode where metadata
// replicated but blob blocks are still missing. Default true so
// existing tests that don't care about the partial-pin path behave
// as if everything is fully replicated.
function mockDrive ({
  version = 0,
  updateOk = true,
  downloadOk = true,
  throwsOnUpdate = false,
  blobsComplete = true,
  blobLength = 8
} = {}) {
  const drive = {
    closed: false,
    closing: false,
    version,
    discoveryKey: Buffer.alloc(32, 0xab),
    update: async () => {
      if (throwsOnUpdate) throw new Error('boom')
      if (!updateOk) await new Promise(resolve => setTimeout(resolve, 100_000))
      drive.version = Math.max(drive.version, 1)
    },
    download: () => {
      const dl = {
        destroyed: false,
        destroy: () => { dl.destroyed = true },
        done: async () => {
          if (!downloadOk) await new Promise(resolve => setTimeout(resolve, 100_000))
        }
      }
      return dl
    },
    blobs: {
      core: {
        length: blobLength,
        has: async (start, end) => {
          if (drive.blobs.core.length === 0) return true
          return blobsComplete
        }
      }
    },
    // Test helper: flip the partial-pin signal mid-test so we can model
    // "first repair pass pulls some blocks, second pass pulls the rest."
    _setBlobsComplete: (v) => { drive.blobs.core.has = async () => v }
  }
  return drive
}

test('repair: returns false when drive missing', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set('aa', { type: 'app' })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('aa')
  t.is(ok, false)
})

test('repair: returns true when already anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 5 })
  reg.set('bb', { type: 'app', drive })
  reg.setAnchored('bb', 5)
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('bb')
  t.is(ok, true)
})

test('repair: succeeds when drive update yields version > 0', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, updateOk: true })
  reg.set('cc', { type: 'app', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('cc', { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, true, 'returns true')
  const e = reg.get('cc')
  t.is(e.anchored, true, 'entry marked anchored')
  t.ok(e.anchoredLength > 0)
})

test('repair: returns false on update timeout', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, updateOk: false })
  reg.set('dd', { type: 'app', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('dd', { updateTimeout: 200, downloadTimeout: 200 })
  t.is(ok, false)
  const e = reg.get('dd')
  t.is(e.anchored, false, 'entry stays unanchored')
})

test('repair: returns false on update throw', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, throwsOnUpdate: true })
  reg.set('ee', { type: 'app', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('ee', { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false)
})

test('runRepairPass: aggregates checked / repaired / stillUnanchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  // 1 already-anchored (skipped)
  const d1 = mockDrive({ version: 3 })
  reg.set('a1', { type: 'app', drive: d1, discoveryKey: d1.discoveryKey })
  reg.setAnchored('a1', 3)
  // 1 will-repair
  const d2 = mockDrive({ version: 0, updateOk: true })
  reg.set('a2', { type: 'app', drive: d2, discoveryKey: d2.discoveryKey })
  // 1 won't-repair (timeout)
  const d3 = mockDrive({ version: 0, updateOk: false })
  reg.set('a3', { type: 'app', drive: d3, discoveryKey: d3.discoveryKey })

  const lifecycle = new AppLifecycle(mockNode(reg))
  // Override default timeouts for fast tests
  lifecycle.repairUnanchored = async function (key) {
    if (key === 'a2') {
      reg.setAnchored(key, 1)
      return true
    }
    return false
  }
  const result = await lifecycle.runRepairPass({ maxConcurrent: 2 })
  t.is(result.checked, 2, 'a1 skipped (anchored)')
  t.is(result.repaired, 1, 'a2 repaired')
  t.is(result.stillUnanchored, 1, 'a3 still unanchored')
})

test('runRepairPass: respects budget', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  for (let i = 0; i < 10; i++) {
    const d = mockDrive()
    reg.set('app' + i, { type: 'app', drive: d, discoveryKey: d.discoveryKey })
  }
  const lifecycle = new AppLifecycle(mockNode(reg))
  lifecycle.repairUnanchored = async () => false // all fail, but counted
  const result = await lifecycle.runRepairPass({ budget: 3 })
  t.is(result.checked, 3, 'budget honored')
})

test('runRepairPass: skips entries without drive', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set('nodrive', { type: 'app' }) // no drive instance
  const d = mockDrive()
  reg.set('hasdrive', { type: 'app', drive: d, discoveryKey: d.discoveryKey })

  const lifecycle = new AppLifecycle(mockNode(reg))
  lifecycle.repairUnanchored = async () => false
  const result = await lifecycle.runRepairPass()
  t.is(result.checked, 1, 'only entry with drive checked')
})

// ─── Partial-pin self-heal (regression coverage for the silent
//     metadata-only "anchored" failure mode patched 2026-05-22) ──────
//
// Before the fix, an entry whose metadata replicated but whose blob
// core still had missing blocks would get marked anchored on the
// strength of drive.version > 0. The periodic repair pass then
// skipped it, so the gap never closed and end users hit indistinguishable
// -from-network-down hangs. See docs/AUTO-HEAL-ROOT-CAUSE-2026-05-22.md.

test('repair: partial pin (metadata replicated, blocks missing) stays unanchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  // Drive replies "metadata synced" but blob core has gaps.
  const drive = mockDrive({ version: 5, updateOk: true, downloadOk: true, blobsComplete: false })
  reg.set('partial', { type: 'app', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored('partial', { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false, 'repair reports failure on partial pin (would have returned true before the fix)')
  const e = reg.get('partial')
  t.is(e.anchored, false, 'entry stays unanchored on partial pin')
})

test('repair: partial pin gets anchored once all blob blocks land', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 5, updateOk: true, downloadOk: true, blobsComplete: false })
  reg.set('eventually', { type: 'app', drive, discoveryKey: drive.discoveryKey })
  const lifecycle = new AppLifecycle(mockNode(reg))

  // First pass: blocks missing → not anchored
  let ok = await lifecycle.repairUnanchored('eventually', { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false)
  t.is(reg.get('eventually').anchored, false)

  // Simulate the next repair tick: peer transmitted the missing blocks.
  drive._setBlobsComplete(true)

  ok = await lifecycle.repairUnanchored('eventually', { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, true, 'repair anchors once blob core is fully present')
  t.is(reg.get('eventually').anchored, true)
})

test('_isDriveFullyReplicated: empty blob core (metadata-only drive) counts as anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const lifecycle = new AppLifecycle(mockNode(reg))
  const drive = mockDrive({ version: 1, blobLength: 0 })
  const ok = await lifecycle._isDriveFullyReplicated(drive)
  t.is(ok, true, 'no blob blocks needed → vacuously fully replicated')
})

test('_isDriveFullyReplicated: closed drive is not anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const lifecycle = new AppLifecycle(mockNode(reg))
  const drive = mockDrive({ version: 1, blobsComplete: true })
  drive.closed = true
  const ok = await lifecycle._isDriveFullyReplicated(drive)
  t.is(ok, false)
})

test('_isDriveFullyReplicated: drive without blob layer is not anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const lifecycle = new AppLifecycle(mockNode(reg))
  const drive = mockDrive({ version: 1 })
  drive.blobs = null // simulate hyperdrive whose blob layer never loaded
  const ok = await lifecycle._isDriveFullyReplicated(drive)
  t.is(ok, false, 'cannot serve content we have no blob core for')
})

test('runRepairPass: re-queues entries the periodic check downgraded from anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const d1 = mockDrive({ version: 3, blobsComplete: false })
  reg.set('p1', { type: 'app', drive: d1, discoveryKey: d1.discoveryKey })
  // Simulate the situation post-_runAnchorCheck on a stale anchored entry
  // (this is the path the fix enables: the periodic check downgrades the
  // entry from anchored:true → false when it detects partial-pin, and
  // runRepairPass MUST re-queue it).
  reg.setAnchored('p1', 3)
  t.is(reg.get('p1').anchored, true, 'starts anchored (pre-detection)')
  reg.clearAnchored('p1', 'simulated partial-pin detection')
  t.is(reg.get('p1').anchored, false, 'periodic check cleared anchored')

  const lifecycle = new AppLifecycle(mockNode(reg))
  let repairCalls = 0
  lifecycle.repairUnanchored = async () => {
    repairCalls++
    return false // simulate "still partial, blocks not all here yet"
  }

  const r = await lifecycle.runRepairPass()
  t.is(r.checked, 1, 'previously-anchored entry is requeued after clearAnchored')
  t.is(repairCalls, 1, 'repairUnanchored invoked')
})

test('catalogForBroadcast includes anchored field', (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set('a', { type: 'app' })
  reg.set('b', { type: 'app' })
  reg.setAnchored('a', 5)
  const broadcast = reg.catalogForBroadcast()
  const a = broadcast.find(x => x.appKey === 'a')
  const b = broadcast.find(x => x.appKey === 'b')
  t.is(a.anchored, true, 'a is anchored')
  t.is(b.anchored, false, 'b is not anchored')
})
