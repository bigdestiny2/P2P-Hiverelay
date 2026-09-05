import test from 'brittle'
import { GenerationPopulation } from 'p2p-hiverelay/core/generation-population.js'
import { StorageAccounting } from 'p2p-hiverelay/core/relay-node/storage-accounting.js'
import { EvictionManager } from 'p2p-hiverelay/core/relay-node/eviction.js'

function appKey (n) {
  return n.toString(16).padStart(64, '0')
}

function fakeDrive (bytes) {
  return {
    core: {
      info: async () => ({ storage: { oplog: 0, tree: 0, blocks: bytes, bitfield: 0 } })
    }
  }
}

function boundedRegistry (entries) {
  const apps = new Map(entries)
  const population = new GenerationPopulation({
    name: 'bounded-runtime-test',
    allowedConsumers: ['storage-accounting', 'eviction', 'dedup-report', 'dedup-reclaim']
  })
  const listeners = new Set()
  const released = []
  for (const key of apps.keys()) population.insert(key)
  return {
    get: key => apps.get(key),
    page (consumer, budget) {
      if (!population.isRegistered(consumer)) population.register(consumer)
      return population.page(consumer, budget, key => apps.get(key))
    },
    releasePopulationConsumer (consumer) {
      released.push(consumer)
      return population.unregister(consumer)
    },
    on (name, listener) {
      if (name === 'change') listeners.add(listener)
    },
    off (name, listener) {
      if (name === 'change') listeners.delete(listener)
    },
    delete (key) {
      if (!apps.delete(key)) return false
      population.delete(key)
      for (const listener of listeners) listener({ type: 'delete', appKey: key })
      return true
    },
    entries () {
      throw new Error('full AppRegistry entries iterator is forbidden')
    },
    keys () {
      throw new Error('full AppRegistry keys iterator is forbidden')
    },
    markEvicted: async () => {},
    released,
    population
  }
}

function eviction (registry, overrides = {}) {
  return new EvictionManager({
    appRegistry: registry,
    seedingRegistry: overrides.seedingRegistry || { getRelaysForApp: async () => [] },
    storageAccounting: {
      getBytes: () => 1,
      measure: async () => 1,
      getSummary: () => ({ totalBytes: 1 })
    },
    diskMonitor: { getInfo: () => ({ usedPct: 95, totalBytes: 1_000_000 }) },
    getReplicationHealth: () => new Map(),
    myPubkeyHex: 'ff'.repeat(32),
    unseed: overrides.unseed || (async () => {}),
    purgeDrive: async () => {}
  }, {
    enabled: true,
    scanBudget: overrides.scanBudget ?? 64,
    maxEvictionsPerSweep: overrides.maxEvictionsPerSweep ?? 20,
    sweepIntervalMs: 60_000
  })
}

test('runtime bounds: accounting pages at 64, publishes top only after a complete cycle, and summarizes O(1)', async (t) => {
  const entries = Array.from({ length: 130 }, (_, i) => [appKey(i + 1), { drive: fakeDrive(i + 1) }])
  const registry = boundedRegistry(entries)
  const accounting = new StorageAccounting({ appRegistry: registry, batchSize: 64, tickMs: 60_000 })

  const first = await accounting._tick()
  t.is(first.examined, 64, 'first turn examines the hard maximum only')
  t.absent(first.complete, 'first page does not claim a complete high-water')
  t.alike(accounting.getTop(10), [], 'partial cycle cannot publish a misleading top list')

  const second = await accounting._tick()
  t.is(second.examined, 64, 'second turn remains bounded')
  t.absent(second.complete, 'second page remains partial')

  const third = await accounting._tick()
  t.is(third.examined, 2, 'terminal page examines only the remainder')
  t.ok(third.complete, 'terminal page commits the aggregate')
  const top = accounting.getTop(100)
  t.is(top.length, 100, 'published top list has a fixed hard cap')
  t.is(top[0].appKey, appKey(130), 'complete-cycle ordering keeps the largest entry')

  accounting._bytes.values = () => { throw new Error('getSummary must not scan measured rows') }
  const summary = accounting.getSummary()
  t.is(summary.measuredEntries, 130)
  t.is(summary.perEntryBytes, (130 * 131) / 2, 'tracked total is available without a Map scan')
  await t.exception.all(() => accounting.getTop(101), /safe integer/)

  await accounting.stop()
  t.ok(registry.released.includes('storage-accounting'), 'stop releases the fixed generation cursor')
})

test('runtime bounds: eviction never reaches a full iterator and advances at most 64 records per turn', async (t) => {
  const entries = Array.from({ length: 130 }, (_, i) => [appKey(i + 1), {
    durability: 1,
    addedAt: 1
  }])
  const registry = boundedRegistry(entries)
  const manager = eviction(registry)

  const first = await manager.sweep({ now: 1_000_000 })
  const second = await manager.sweep({ now: 1_000_000 })
  const third = await manager.sweep({ now: 1_000_000 })
  t.alike([first.examined, second.examined, third.examined], [64, 64, 2])
  t.alike([first.complete, second.complete, third.complete], [false, false, true])
  t.is(first.skips.archive, 64, 'filter rejects consume the normal page budget')

  await manager.stop()
  t.ok(registry.released.includes('eviction'), 'stop releases the eviction cursor')
})

test('runtime bounds: invalid eviction/accounting budgets fail instead of clamping', async (t) => {
  const registry = boundedRegistry([])
  await t.exception.all(() => new StorageAccounting({ appRegistry: registry, batchSize: 65 }), /safe integer/)
  await t.exception.all(() => eviction(registry, { scanBudget: 65 }), /safe integer/)
  await t.exception.all(() => eviction(registry, { maxEvictionsPerSweep: 65 }), /safe integer/)
})

test('runtime bounds: eviction stop fences post-await work and drains the active page', async (t) => {
  let releaseLookup
  const lookup = new Promise(resolve => { releaseLookup = resolve })
  const key = appKey(1)
  const registry = boundedRegistry([[key, { durability: 0, addedAt: 1 }]])
  let unseeded = 0
  const manager = eviction(registry, {
    seedingRegistry: {
      getRelaysForApp: async () => {
        await lookup
        return [{ relayPubkey: 'ff'.repeat(32) }, { relayPubkey: 'ee'.repeat(32) }, { relayPubkey: 'dd'.repeat(32) }, { relayPubkey: 'cc'.repeat(32) }]
      }
    },
    unseed: async () => { unseeded++ }
  })
  manager.deps.getReplicationHealth = () => new Map([[key, { current: 4, target: 2 }]])

  const sweep = manager.sweep({ now: 10 * 24 * 60 * 60 * 1000 })
  await Promise.resolve()
  const stopped = manager.stop()
  releaseLookup()
  await Promise.all([sweep, stopped])
  t.is(unseeded, 0, 'no unseed begins after the stop fence')
  t.ok(registry.released.includes('eviction'), 'drained stop releases ownership')
})
