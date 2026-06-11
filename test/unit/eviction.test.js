/**
 * Phase 0 + A tests: StorageAccounting + EvictionManager + tombstones.
 *
 * Context (2026-06-11): fleet restarts let replication-repair adopt the
 * union of all catalogs (5/5 replicas at floor 2) while the storage
 * guard compared against the always-zero seeder.totalBytesStored — disks
 * filled to 100%. Phase 0 measures real bytes; Phase A sheds surplus
 * replicas under pressure without ever touching archive/custody entries
 * or breaching the floor, and tombstones stop resurrection.
 */

import test from 'brittle'
import { mkdtemp } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { StorageAccounting } from 'p2p-hiverelay/core/relay-node/storage-accounting.js'
import { EvictionManager, xorDistance } from 'p2p-hiverelay/core/relay-node/eviction.js'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

// ─── fixtures ──────────────────────────────────────────────────────

function fakeDrive (metaBytes, blobBytes) {
  const core = (n) => ({
    info: async (opts) => ({
      storage: opts && opts.storage ? { oplog: 10, tree: 20, blocks: n, bitfield: 5 } : null
    })
  })
  return { core: core(metaBytes), blobs: blobBytes != null ? { core: core(blobBytes) } : null }
}

function fakeRegistry (entries) {
  const map = new Map(entries)
  const evicted = new Map()
  return {
    get: (k) => map.get(k),
    keys: () => map.keys(),
    entries: () => map.entries(),
    delete: (k) => map.delete(k),
    markEvicted: (k, at) => evicted.set(k, at || Date.now()),
    isEvicted: (k) => evicted.has(k),
    clearEvicted: (k) => evicted.delete(k),
    _evicted: evicted,
    _map: map
  }
}

const NOW = Date.UTC(2026, 5, 11, 12, 0, 0)
const OLD = NOW - 10 * 24 * 60 * 60 * 1000 // 10 days — past minAge

// 64-hex keys engineered so xor-distance ranks are predictable.
const APP = 'aa'.repeat(32)
const MY_PK = '00'.repeat(32) // distance from APP: aa... (far)
const NEAR_PK = 'aa'.repeat(31) + 'ab' // distance ~ 00..01 (near)
const MID_PK = '55'.repeat(32) // distance ff.. (farthest)

function makeEviction (over = {}) {
  const entries = over.entries || [[APP, { durability: 0, custodyIntentId: null, addedAt: OLD, drive: fakeDrive(100, 1000) }]]
  const registry = over.registry || fakeRegistry(entries)
  const health = over.health || new Map([[APP, { current: 4, target: 2 }]])
  const holders = over.holders || [MY_PK, NEAR_PK, MID_PK, 'bb'.repeat(32)]
  const unseeded = []
  const purged = []
  const ev = new EvictionManager({
    appRegistry: registry,
    seedingRegistry: { getRelaysForApp: async () => holders.map(pk => ({ relayPubkey: pk })) },
    storageAccounting: over.accounting || {
      getBytes: () => 5000,
      measure: async () => 5000,
      getSummary: () => ({ totalBytes: 5000 })
    },
    diskMonitor: { getInfo: () => (over.disk || { usedPct: 92, totalBytes: 20e9 }) },
    getReplicationHealth: () => health,
    myPubkeyHex: over.myPubkey || MY_PK,
    unseed: async (k) => { unseeded.push(k); registry._map && registry._map.delete(k) },
    purgeDrive: async (k) => { purged.push(k) }
  }, { enabled: true, minAgeMs: 3 * 24 * 60 * 60 * 1000, ...over.config })
  return { ev, registry, unseeded, purged }
}

// ─── StorageAccounting ─────────────────────────────────────────────

test('accounting: measures meta+blob file bytes per entry and totals', async (t) => {
  const reg = fakeRegistry([
    ['k1', { drive: fakeDrive(1000, 5000) }],
    ['k2', { drive: fakeDrive(200, null) }]
  ])
  const acc = new StorageAccounting({ appRegistry: reg, tickMs: 60_000, batchSize: 10 })
  await acc._tick()
  // k1: meta(10+20+1000+5) + blobs(10+20+5000+5) = 6070 ; k2: 235
  t.is(acc.getBytes('k1'), 6070, 'meta+blob summed from file stats')
  t.is(acc.getBytes('k2'), 235, 'metadata-only drive measured')
  t.is(acc.getSummary().totalBytes, 6305, 'summary totals all measured entries')
  acc.stop()
})

test('accounting: paces in batches and prunes removed entries', async (t) => {
  const reg = fakeRegistry([['a', { drive: fakeDrive(1, 1) }], ['b', { drive: fakeDrive(2, 2) }], ['c', { drive: fakeDrive(3, 3) }]])
  const acc = new StorageAccounting({ appRegistry: reg, tickMs: 60_000, batchSize: 2 })
  await acc._tick()
  t.is(acc.getSummary().measuredEntries, 2, 'first tick measures only batchSize entries')
  await acc._tick()
  t.is(acc.getSummary().measuredEntries, 3, 'second tick completes the pass')
  reg._map.delete('b')
  await acc._tick() // wraps: cursor reset + prune
  t.absent([...reg._map.keys()].includes('b'), 'entry removed from registry')
  await acc._tick(); await acc._tick()
  t.is(acc.getBytes('b'), null, 'cache pruned for removed entry')
  acc.stop()
})

// ─── EvictionManager policy ────────────────────────────────────────

test('eviction: below disk pressure -> no-op', async (t) => {
  const { ev, unseeded } = makeEviction({ disk: { usedPct: 50, totalBytes: 20e9 } })
  const res = await ev.sweep({ now: NOW })
  t.is(res.skipped, 'below-pressure', 'gated on pressure')
  t.is(unseeded.length, 0, 'nothing unseeded')
})

test('eviction: archive tier, custody-bound, young, and census-less entries are untouchable', async (t) => {
  const entries = [
    ['11'.repeat(32), { durability: 1, addedAt: OLD, drive: fakeDrive(1, 1) }], // archive pin
    ['22'.repeat(32), { durability: 0, custodyIntentId: 'intent-x', addedAt: OLD, drive: fakeDrive(1, 1) }],
    ['33'.repeat(32), { durability: 0, addedAt: NOW - 1000, drive: fakeDrive(1, 1) }], // too young
    ['44'.repeat(32), { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }] // no census row
  ]
  const health = new Map([
    ['11'.repeat(32), { current: 5, target: 2 }],
    ['22'.repeat(32), { current: 5, target: 2 }],
    ['33'.repeat(32), { current: 5, target: 2 }]
    // 44.. deliberately absent
  ])
  const { ev, unseeded } = makeEviction({ entries, health })
  const res = await ev.sweep({ now: NOW })
  t.is(res.candidates, 0, 'no candidates')
  t.is(unseeded.length, 0, 'nothing evicted')
})

test('eviction: floor math — only sheds when remaining ≥ target + margin', async (t) => {
  // current=3, target=2, margin=1: we leave -> remaining 2 < 3 -> skip
  let { ev, unseeded } = makeEviction({ health: new Map([[APP, { current: 3, target: 2 }]]) })
  await ev.sweep({ now: NOW })
  t.is(unseeded.length, 0, 'current=3 keeps the entry (would breach target+margin)')

  // current=4: remaining 3 ≥ 3 -> eligible (we are MID-distance? ensure rank passes by making us farthest)
  ;({ ev, unseeded } = makeEviction({
    myPubkey: MID_PK,
    holders: [MID_PK, NEAR_PK, MY_PK, 'bb'.repeat(32)],
    health: new Map([[APP, { current: 4, target: 2 }]])
  }))
  await ev.sweep({ now: NOW })
  t.is(unseeded.length, 1, 'current=4 sheds one copy')
  t.is(unseeded[0], APP, 'the surplus entry was evicted')
})

test('eviction: deterministic stagger — only the farthest K holders shed', async (t) => {
  // surplus K = remaining - (target+margin) + 1 = (4-1) - 3 + 1 = 1 -> only THE farthest sheds.
  // MID_PK (0x55..) xor APP (0xaa..) = 0xff.. = farthest; MY_PK (0x00) -> 0xaa.. = second.
  const holders = [MY_PK, NEAR_PK, MID_PK]
  let { ev, unseeded } = makeEviction({ myPubkey: MY_PK, holders, health: new Map([[APP, { current: 4, target: 2 }]]) })
  await ev.sweep({ now: NOW })
  t.is(unseeded.length, 0, 'second-farthest holder defers')

  ;({ ev, unseeded } = makeEviction({ myPubkey: MID_PK, holders, health: new Map([[APP, { current: 4, target: 2 }]]) }))
  await ev.sweep({ now: NOW })
  t.is(unseeded.length, 1, 'farthest holder sheds')
})

test('eviction: evicts biggest-first, respects maxEvictionsPerSweep + resumePct, tombstones each', async (t) => {
  const k1 = 'aa'.repeat(32); const k2 = 'ab' + 'aa'.repeat(31); const k3 = 'ac' + 'aa'.repeat(31)
  const entries = [
    [k1, { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }],
    [k2, { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }],
    [k3, { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }]
  ]
  const sizes = { [k1]: 1e9, [k2]: 5e9, [k3]: 3e9 }
  const health = new Map(Object.keys(sizes).map(k => [k, { current: 5, target: 2 }]))
  const { ev, registry, unseeded, purged } = makeEviction({
    entries,
    health,
    myPubkey: MID_PK,
    holders: [MID_PK], // sole counted holder unrealistic but rank-passes; remaining=4≥3
    accounting: { getBytes: (k) => sizes[k], measure: async (k) => sizes[k], getSummary: () => ({ totalBytes: 9e9 }) },
    disk: { usedPct: 92, totalBytes: 20e9 },
    // resumePct low enough that the per-sweep cap is what binds here —
    // the resumePct early-stop has its own dedicated test below.
    config: { maxEvictionsPerSweep: 2, resumePct: 40 }
  })
  const res = await ev.sweep({ now: NOW })
  t.is(unseeded.length, 2, 'capped at maxEvictionsPerSweep')
  t.alike(unseeded, [k2, k3], 'biggest entries shed first')
  t.alike(purged, unseeded, 'every eviction purges the drive cores')
  t.ok(registry.isEvicted(k2) && registry.isEvicted(k3), 'tombstoned')
  t.absent(registry.isEvicted(k1), 'survivor not tombstoned')
  t.is(res.freedBytes, 8e9, 'freed bytes accounted')
  t.is(ev.getSummary().evictedTotal, 2, 'summary counts evictions')
})

test('eviction: resumePct stops early once projection clears pressure', async (t) => {
  const k1 = 'aa'.repeat(32); const k2 = 'ab' + 'aa'.repeat(31)
  const entries = [
    [k1, { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }],
    [k2, { durability: 0, addedAt: OLD, drive: fakeDrive(1, 1) }]
  ]
  const health = new Map([[k1, { current: 5, target: 2 }], [k2, { current: 5, target: 2 }]])
  // 20 GB volume at 92%; first eviction frees 6 GB -> projected 62% ≤ 70 -> stop.
  const { ev, unseeded } = makeEviction({
    entries,
    health,
    myPubkey: MID_PK,
    holders: [MID_PK],
    accounting: { getBytes: () => 6e9, measure: async () => 6e9, getSummary: () => ({ totalBytes: 12e9 }) },
    config: { maxEvictionsPerSweep: 20, resumePct: 70 }
  })
  await ev.sweep({ now: NOW })
  t.is(unseeded.length, 1, 'stopped after pressure projected below resumePct')
})

test('eviction: census fallback — acceptance records stand in for missing health rows', async (t) => {
  // No health row at all; 4 acceptance records; targetFloor 2 + margin 1:
  // remaining 3 ≥ 3 -> evictable by the farthest holder.
  const holders = [MID_PK, NEAR_PK, MY_PK, 'bb'.repeat(32)]
  let { ev, unseeded } = makeEviction({
    myPubkey: MID_PK,
    holders,
    health: new Map(), // <- the 417-of-961 case from the utah canary
    config: { targetFloor: 2 }
  })
  let res = await ev.sweep({ now: NOW })
  t.is(res.skips.censusFallback, 1, 'fallback census used (and counted)')
  t.is(unseeded.length, 1, 'evicted via acceptance-record census')

  // Same but only 3 holders: remaining 2 < 3 -> floor blocks it.
  ;({ ev, unseeded } = makeEviction({
    myPubkey: MID_PK,
    holders: [MID_PK, NEAR_PK, MY_PK],
    health: new Map(),
    config: { targetFloor: 2 }
  }))
  res = await ev.sweep({ now: NOW })
  t.is(res.skips.floor, 1, 'floor still binds under fallback census')
  t.is(unseeded.length, 0, 'nothing evicted')

  // No acceptance records either -> never evict blind.
  ;({ ev, unseeded } = makeEviction({ myPubkey: MID_PK, holders: [], health: new Map(), config: { targetFloor: 2 } }))
  res = await ev.sweep({ now: NOW })
  t.is(res.skips.noCensus, 1, 'entries with zero census stay untouchable')
  t.is(unseeded.length, 0, 'nothing evicted blind')
})

// ─── xorDistance ───────────────────────────────────────────────────

test('xorDistance: bytewise xor, stable and symmetric', (t) => {
  const d1 = xorDistance('00'.repeat(32), 'aa'.repeat(32))
  const d2 = xorDistance('aa'.repeat(32), '00'.repeat(32))
  t.is(d1.toString('hex'), 'aa'.repeat(32), 'xor of 00 and aa is aa')
  t.is(d1.toString('hex'), d2.toString('hex'), 'symmetric')
})

// ─── AppRegistry tombstone persistence ─────────────────────────────

test('tombstones: survive a registry reload (sidecar, atomic)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'evict-reg-'))
  const reg1 = new AppRegistry(dir)
  reg1.markEvicted('cc'.repeat(32), NOW)
  reg1.markEvicted('dd'.repeat(32), NOW + 1)
  await reg1._evictedPersistTail // let the atomic write land
  const { readdir } = await import('fs/promises')
  const files = await readdir(dir)
  t.ok(files.includes('evicted.json'), 'sidecar written')
  t.absent(files.some(f => f.endsWith('.tmp')), 'no tmp orphan')

  const reg2 = new AppRegistry(dir)
  await reg2.load()
  t.ok(reg2.isEvicted('cc'.repeat(32)), 'tombstone survived reload')
  t.ok(reg2.isEvicted('dd'.repeat(32)), 'both survived')
  reg2.clearEvicted('cc'.repeat(32))
  await reg2._evictedPersistTail
  const reg3 = new AppRegistry(dir)
  await reg3.load()
  t.absent(reg3.isEvicted('cc'.repeat(32)), 'clearEvicted persisted (under-floor re-adopt path)')
  t.ok(reg3.isEvicted('dd'.repeat(32)), 'other tombstone intact')
})
