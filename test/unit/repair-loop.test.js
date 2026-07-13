import test from 'brittle'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'

const REPAIR_BOUND = 16 * 1024 * 1024

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'repair-test-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

function appKey (label) {
  return Buffer.from(label).toString('hex').padEnd(64, '0').slice(0, 64)
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
    config: opts.config || {},
    storageAdmission: opts.storageAdmission || {
      canAcknowledge: () => true,
      runKeyMutation: (_key, run) => Promise.resolve().then(run)
    }
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
  let blobBlocksComplete = blobsComplete
  const range = (blob = false) => ({
    async done () {
      if (!downloadOk || (blob && !blobBlocksComplete)) throw new Error('incomplete range')
    },
    async downloaded () {
      if (!downloadOk || (blob && !blobBlocksComplete)) throw new Error('incomplete range')
    },
    destroy () {}
  })
  const snapshot = (core, blob = false) => ({
    fork: core.fork,
    length: core.length,
    byteLength: core.byteLength,
    async ready () {},
    download: () => range(blob),
    async close () {}
  })
  const metaCore = {
    fork: 0,
    length: Math.max(0, version),
    byteLength: 1024,
    async update () {},
    snapshot () { return snapshot(this) }
  }
  const blobCore = {
    fork: 0,
    length: blobLength,
    byteLength: blobLength * 1024,
    async update () {},
    has: async () => blobBlocksComplete,
    snapshot () { return snapshot(this, true) }
  }
  const drive = {
    closed: false,
    closing: false,
    version,
    discoveryKey: Buffer.alloc(32, 0xab),
    db: {
      core: metaCore
    },
    update: async () => {
      if (throwsOnUpdate) throw new Error('boom')
      if (!updateOk) {
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 100_000)
          if (timer.unref) timer.unref()
        })
      }
      drive.version = Math.max(drive.version, 1)
      metaCore.length = drive.version
    },
    download: () => range(true),
    blobs: {
      core: blobCore
    },
    // Test helper: flip the partial-pin signal mid-test so we can model
    // "first repair pass pulls some blocks, second pass pulls the rest."
    _setBlobsComplete: (v) => { blobBlocksComplete = v }
  }
  return drive
}

test('repair: returns false when drive missing', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('aa'), { type: 'app' })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('aa'))
  t.is(ok, false)
})

test('repair: returns true when already anchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 5 })
  reg.set(appKey('bb'), { type: 'app', drive })
  reg.setAnchored(appKey('bb'), 5)
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('bb'))
  t.is(ok, true)
})

test('repair: succeeds when drive update yields version > 0', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, updateOk: true })
  reg.set(appKey('cc'), { type: 'app', drive, discoveryKey: drive.discoveryKey, maxStorage: REPAIR_BOUND })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('cc'), { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, true, 'returns true')
  const e = reg.get(appKey('cc'))
  t.is(e.anchored, true, 'entry marked anchored')
  t.ok(e.anchoredLength > 0)
})

test('repair: returns false on update timeout', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, updateOk: false })
  reg.set(appKey('dd'), { type: 'app', drive, discoveryKey: drive.discoveryKey, maxStorage: REPAIR_BOUND })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('dd'), { updateTimeout: 200, downloadTimeout: 200 })
  t.is(ok, false)
  const e = reg.get(appKey('dd'))
  t.is(e.anchored, false, 'entry stays unanchored')
})

test('repair: returns false on update throw', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 0, throwsOnUpdate: true })
  reg.set(appKey('ee'), { type: 'app', drive, discoveryKey: drive.discoveryKey, maxStorage: REPAIR_BOUND })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('ee'), { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false)
})

test('runRepairPass: aggregates checked / repaired / stillUnanchored', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  // 1 already-anchored (skipped)
  const d1 = mockDrive({ version: 3 })
  reg.set(appKey('a1'), { type: 'app', drive: d1, discoveryKey: d1.discoveryKey })
  reg.setAnchored(appKey('a1'), 3)
  // 1 will-repair
  const d2 = mockDrive({ version: 0, updateOk: true })
  reg.set(appKey('a2'), { type: 'app', drive: d2, discoveryKey: d2.discoveryKey })
  // 1 won't-repair (timeout)
  const d3 = mockDrive({ version: 0, updateOk: false })
  reg.set(appKey('a3'), { type: 'app', drive: d3, discoveryKey: d3.discoveryKey })

  const lifecycle = new AppLifecycle(mockNode(reg))
  // Override default timeouts for fast tests
  lifecycle.repairUnanchored = async function (key) {
    if (key === appKey('a2')) {
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
    reg.set(appKey('app' + i), { type: 'app', drive: d, discoveryKey: d.discoveryKey })
  }
  const lifecycle = new AppLifecycle(mockNode(reg))
  lifecycle.repairUnanchored = async () => false // all fail, but counted
  const result = await lifecycle.runRepairPass({ budget: 3 })
  t.is(result.checked, 3, 'budget honored')
})

test('runRepairPass: skips entries without drive', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('nodrive'), { type: 'app' }) // no drive instance
  const d = mockDrive()
  reg.set(appKey('hasdrive'), { type: 'app', drive: d, discoveryKey: d.discoveryKey })

  const lifecycle = new AppLifecycle(mockNode(reg))
  lifecycle.repairUnanchored = async () => false
  const result = await lifecycle.runRepairPass()
  t.is(result.checked, 1, 'only entry with drive checked')
})

test('repair: refuses to anchor when an exact core snapshot is unavailable', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 5, blobsComplete: true })
  drive.blobs.core.snapshot = undefined
  reg.set(appKey('no-snapshot'), {
    type: 'app',
    drive,
    discoveryKey: drive.discoveryKey,
    maxStorage: REPAIR_BOUND
  })
  const lifecycle = new AppLifecycle(mockNode(reg))

  const ok = await lifecycle.repairUnanchored(appKey('no-snapshot'), {
    updateTimeout: 500,
    downloadTimeout: 500
  })
  t.is(ok, false, 'missing pinned blob proof fails closed')
  t.is(reg.get(appKey('no-snapshot')).anchored, false)
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
  reg.set(appKey('partial'), { type: 'app', drive, discoveryKey: drive.discoveryKey, maxStorage: REPAIR_BOUND })
  const lifecycle = new AppLifecycle(mockNode(reg))
  const ok = await lifecycle.repairUnanchored(appKey('partial'), { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false, 'repair reports failure on partial pin (would have returned true before the fix)')
  const e = reg.get(appKey('partial'))
  t.is(e.anchored, false, 'entry stays unanchored on partial pin')
})

test('repair: partial pin gets anchored once all blob blocks land', async (t) => {
  const { dir, cleanup } = tmpDir(); t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const drive = mockDrive({ version: 5, updateOk: true, downloadOk: true, blobsComplete: false })
  reg.set(appKey('eventually'), { type: 'app', drive, discoveryKey: drive.discoveryKey, maxStorage: REPAIR_BOUND })
  const lifecycle = new AppLifecycle(mockNode(reg))

  // First pass: blocks missing → not anchored
  let ok = await lifecycle.repairUnanchored(appKey('eventually'), { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, false)
  t.is(reg.get(appKey('eventually')).anchored, false)

  // Simulate the next repair tick: peer transmitted the missing blocks.
  drive._setBlobsComplete(true)

  ok = await lifecycle.repairUnanchored(appKey('eventually'), { updateTimeout: 500, downloadTimeout: 500 })
  t.is(ok, true, 'repair anchors once blob core is fully present')
  t.is(reg.get(appKey('eventually')).anchored, true)
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
  reg.set(appKey('p1'), { type: 'app', drive: d1, discoveryKey: d1.discoveryKey })
  // Simulate the situation post-_runAnchorCheck on a stale anchored entry
  // (this is the path the fix enables: the periodic check downgrades the
  // entry from anchored:true → false when it detects partial-pin, and
  // runRepairPass MUST re-queue it).
  reg.setAnchored(appKey('p1'), 3)
  t.is(reg.get(appKey('p1')).anchored, true, 'starts anchored (pre-detection)')
  reg.clearAnchored(appKey('p1'), 'simulated partial-pin detection')
  t.is(reg.get(appKey('p1')).anchored, false, 'periodic check cleared anchored')

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
  reg.set(appKey('a'), { type: 'app' })
  reg.set(appKey('b'), { type: 'app' })
  reg.setAnchored(appKey('a'), 5)
  const broadcast = reg.catalogForBroadcast()
  const a = broadcast.find(x => x.appKey === appKey('a'))
  const b = broadcast.find(x => x.appKey === appKey('b'))
  t.is(a.anchored, true, 'a is anchored')
  t.is(b.anchored, false, 'b is not anchored')
})
