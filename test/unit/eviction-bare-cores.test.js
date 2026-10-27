/**
 * EvictionManager bare-core pass (v0.24.5).
 *
 * Production bug (2026-10-26): disk-pressure eviction only considered
 * app-registry entries, so with aggressive settings it evicted hundreds of
 * tiny apps while freeing 0 bytes of the pinned PearTube video that filled
 * the disk. The sweep now also sheds seeder bare-core pins, least-recently-
 * served first, under the same gate / resumePct / minAgeMs config, never the
 * catalog bee, never our own (writable) or operator ('local') pins.
 *
 * Same dependency-injected fixture style as eviction.test.js.
 */

import test from 'brittle'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { EvictionManager } from 'p2p-hiverelay/core/relay-node/eviction.js'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

const NOW = Date.UTC(2026, 9, 26, 12, 0, 0)
const DAY = 24 * 60 * 60 * 1000
const OLD = NOW - 10 * DAY
const CATALOG = 'ca'.repeat(32)

function key (n) { return n.toString(16).padStart(2, '0').repeat(32) }

function emptyRegistry () {
  const map = new Map()
  return {
    get: (k) => map.get(k),
    keys: () => map.keys(),
    entries: () => map.entries(),
    markEvicted () {},
    isEvicted: () => false
  }
}

function makeEviction ({ pins, disk = { usedPct: 90, totalBytes: 1000 }, config = {}, refuse = {}, catalogBeeKey = CATALOG } = {}) {
  const live = new Map(pins.map(p => [p.key, { ...p }]))
  const evictCalls = []
  const events = []
  const ev = new EvictionManager({
    appRegistry: emptyRegistry(),
    seedingRegistry: { getRelaysForApp: async () => [] },
    storageAccounting: { getBytes: () => 0, measure: async () => 0, getSummary: () => ({ totalBytes: 0 }) },
    diskMonitor: { getInfo: () => disk },
    getReplicationHealth: () => new Map(),
    myPubkeyHex: '00'.repeat(32),
    unseed: async () => {},
    purgeDrive: async () => {},
    getCatalogBeeKey: () => catalogBeeKey,
    bareCores: {
      list: () => [...live.values()],
      evict: async (k) => {
        evictCalls.push(k)
        if (refuse[k]) return { evicted: false, skipped: refuse[k], freedBytes: 0, purged: false }
        const pin = live.get(k)
        live.delete(k)
        return { evicted: true, purged: true, freedBytes: pin.bytesStored }
      }
    }
  }, { enabled: true, diskPressurePct: 80, resumePct: 70, minAgeMs: 3 * DAY, ...config })
  ev.on('evicted-core', (e) => events.push(e))
  return { ev, evictCalls, events, live }
}

function pin (n, over = {}) {
  return { key: key(n), bytesStored: 100, pinnedAt: OLD, lastServedAt: 0, source: 'seed-request', writable: false, ...over }
}

test('bare cores: least-recently-served first, stop once projected below resumePct', async (t) => {
  // 1000-byte volume at 90%: shedding must free > 200 bytes to reach 70%.
  const { ev, evictCalls, events } = makeEviction({
    pins: [
      pin(1, { lastServedAt: NOW - 1 * DAY, bytesStored: 300 }), // served yesterday — keep
      pin(2, { lastServedAt: NOW - 5 * DAY }),
      pin(3, { lastServedAt: 0, bytesStored: 50 }), //               never served — first
      pin(4, { lastServedAt: NOW - 9 * DAY })
    ]
  })
  const res = await ev.sweep({ now: NOW })

  t.alike(evictCalls, [key(3), key(4), key(2)], 'never-served, then oldest lastServedAt')
  t.alike(res.evictedCores, [key(3), key(4), key(2)])
  t.is(res.freedBytes, 250, '90% -> 65%: stopped after crossing resumePct')
  t.absent(evictCalls.includes(key(1)), 'recently served pin survives')
  t.alike(events.map(e => e.freedBytes), [50, 100, 100], 'each eviction logged with freedBytes')
  t.is(events[0].coreKey, key(3))
  t.is(ev.getSummary().evictedCoresTotal, 3)
  t.is(ev.getSummary().freedBytesTotal, 250)
})

test('bare cores: never young, catalog bee, writable or operator pins; empty pins skipped', async (t) => {
  const { ev, evictCalls, events } = makeEviction({
    pins: [
      pin(1, { pinnedAt: NOW - 1 * 60 * 60 * 1000 }), //       younger than minAgeMs
      { ...pin(2), key: CATALOG }, //                          the advertised catalog bee
      pin(3, { writable: true }), //                           our own data (outboxlog)
      pin(4, { source: 'local' }), //                          operator /seed-core pin
      pin(5, { bytesStored: 0 }), //                           frees nothing
      pin(6, { source: 'legacy', pinnedAt: 0 }) //             pre-v0.24.5 pin: no pin time -> old
    ],
    disk: { usedPct: 99, totalBytes: 1000 }
  })
  const res = await ev.sweep({ now: NOW })

  t.alike(evictCalls, [key(6)], 'only the legacy video pin is shed')
  t.alike(res.coreSkips, { catalogBee: 1, writable: 1, local: 1, young: 1, empty: 1 })
  t.is(events.length, 1)
})

test('bare cores: below pressure (and under cap) nothing is shed', async (t) => {
  const { ev, evictCalls } = makeEviction({ pins: [pin(1)], disk: { usedPct: 50, totalBytes: 1000 } })
  const res = await ev.sweep({ now: NOW })
  t.is(res.skipped, 'below-pressure')
  t.is(evictCalls.length, 0)
})

test('bare cores: own maxEvictionsPerSweep budget; seeder refusals are skips', async (t) => {
  const pins = []
  for (let i = 1; i <= 6; i++) pins.push(pin(i, { lastServedAt: i }))
  const { ev, evictCalls } = makeEviction({
    pins,
    disk: { usedPct: 99, totalBytes: 100_000 }, // nothing gets us under resumePct
    config: { maxEvictionsPerSweep: 3 },
    refuse: { [key(2)]: 'protected' } // e.g. a live app drive's blobs core
  })
  const res = await ev.sweep({ now: NOW })
  t.alike(evictCalls, [key(1), key(2), key(3), key(4)], 'refused pin does not consume the budget')
  t.alike(res.evictedCores, [key(1), key(3), key(4)], 'capped at maxEvictionsPerSweep')
  t.is(res.coreSkips.protected, 1)
})

test('bare cores: over the designated cap sheds even below disk pressure', async (t) => {
  const { ev, evictCalls } = makeEviction({
    pins: [pin(1, { bytesStored: 400 }), pin(2, { bytesStored: 400, lastServedAt: NOW - DAY })],
    disk: { usedPct: 40, totalBytes: 100_000 }
  })
  ev.deps.storageAccounting = { getBytes: () => 0, measure: async () => 0, getSummary: () => ({ totalBytes: 1000 }) }
  ev._getStorageCap = () => 700
  const res = await ev.sweep({ now: NOW })
  t.absent(res.skipped)
  t.alike(evictCalls, [key(1)], 'one 400-byte pin brings 1000 under the 700 cap')
})

test('node wiring: real Seeder pins flow through _ensureEviction; catalog bee survives, video is purged', async (t) => {
  const purged = []
  const store = {
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      const core = new EventEmitter()
      Object.assign(core, {
        key,
        discoveryKey: b4a.alloc(32, 3),
        length: 0,
        byteLength: 0,
        writable: false,
        async ready () {},
        async info () { return { length: 0, byteLength: 0, contiguousLength: 0, storage: { oplog: 0, tree: 0, blocks: 400, bitfield: 0 } } },
        download () { return { done: () => new Promise(() => {}), destroy () {} } },
        async close () {},
        async purge () { purged.push(hex) }
      })
      return core
    }
  }
  const node = new RelayNode({ storage: path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex')), enableAPI: false })
  node.swarm = { keyPair: { publicKey: randomBytes(32) } }
  node.seedingRegistry = { getRelaysForApp: async () => [] }
  node.storageAccounting = { getBytes: () => null, measure: async () => 0, getSummary: () => ({ totalBytes: 0 }) }
  node.diskMonitor = { criticalThreshold: 95, getInfo: () => ({ usedPct: 99, totalBytes: 1000, freeBytes: 10 }) }
  node.catalogBeeKey = CATALOG
  node.config.eviction = { enabled: true, minAgeMs: 0 }
  node.seeder = new Seeder(store, { join () {}, async leave () {} }, {
    isProtectedCore: (k) => node._isProtectedBareCore(k)
  })
  await node.seeder.start()
  t.teardown(async () => {
    if (node.eviction) node.eviction.stop()
    await node.seeder.stop()
  })

  const video = key(7)
  // Even pinned as a seed-request (e.g. a legacy entry), the catalog bee is exempt.
  await node.seeder.seedCore(CATALOG, { maxStorageBytes: 1000, source: 'seed-request' })
  await node.seeder.seedCore(video, { maxStorageBytes: 1000, group: key(9), source: 'seed-request' })

  const logged = []
  node.on('core-eviction', (e) => logged.push(e))
  const ev = node._ensureEviction()
  const res = await ev.sweep({ now: Date.now() + 1 })

  t.alike(res.evictedCores, [video])
  t.is(res.coreSkips.catalogBee, 1)
  t.alike(purged, [video], 'evicted pin purged from disk')
  t.ok(node.seeder.cores.has(CATALOG), 'catalog bee still pinned')
  t.is(logged.length, 1, 'node re-emits for the operator log')
  t.is(logged[0].coreKey, video)
  t.is(logged[0].freedBytes, 400)
})

test('no bareCores dep: sweep summary unchanged (app-only relays)', async (t) => {
  const ev = new EvictionManager({
    appRegistry: emptyRegistry(),
    seedingRegistry: { getRelaysForApp: async () => [] },
    storageAccounting: { getBytes: () => 0, measure: async () => 0, getSummary: () => ({ totalBytes: 0 }) },
    diskMonitor: { getInfo: () => ({ usedPct: 90, totalBytes: 1000 }) },
    getReplicationHealth: () => new Map(),
    myPubkeyHex: '00'.repeat(32),
    unseed: async () => {}
  }, { enabled: true })
  const res = await ev.sweep({ now: NOW })
  t.absent('evictedCores' in res)
  t.alike(res.evicted, [])
})
