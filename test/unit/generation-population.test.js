import test from 'brittle'
import { GenerationPopulation } from '../../packages/core/core/generation-population.js'
import { CompletionScheduler } from '../../packages/core/core/completion-scheduler.js'
import { AppRegistry } from '../../packages/core/core/app-registry.js'

test('generation population fences inserts and revisits unchanged membership', (t) => {
  const values = new Map([['a', 1], ['b', 2], ['c', 3]])
  const population = new GenerationPopulation({ name: 'test', allowedConsumers: ['pass'] })
  for (const key of values.keys()) population.insert(key)
  population.register('pass')

  const first = population.page('pass', 2, key => values.get(key))
  t.alike(first.entries.map(entry => entry.key), ['a', 'b'])
  t.is(first.examined, 2)
  t.is(first.complete, false)

  values.set('d', 4)
  population.insert('d')
  const second = population.page('pass', 2, key => values.get(key))
  t.alike(second.entries.map(entry => entry.key), ['c'], 'post-fence insert is deferred')
  t.is(second.complete, true)

  const nextCycle = population.page('pass', 4, key => values.get(key))
  t.alike(nextCycle.entries.map(entry => entry.key), ['a', 'b', 'c', 'd'])
  t.is(nextCycle.complete, true)
})

test('generation population delete/reinsert consumes fences and tombstone budget', (t) => {
  const values = new Map([['a', 1]])
  const population = new GenerationPopulation({ name: 'test', allowedConsumers: ['pass'] })
  population.insert('a')
  values.delete('a')
  population.delete('a')
  values.set('a', 2)
  population.insert('a')
  population.register('pass')
  const page = population.page('pass', 2, key => values.get(key))
  t.is(page.examined, 2, 'deleted member and tombstone both consume budget')
  t.alike(page.entries, [])
  t.is(page.complete, false)
  const next = population.page('pass', 3, key => values.get(key))
  t.alike(next.entries.map(entry => entry.value), [2])
  t.ok(next.reclaimed <= 64)
})

test('generation population rejects invalid consumers, budgets and backpressure', async (t) => {
  const population = new GenerationPopulation({ name: 'test', maxRecords: 2, allowedConsumers: ['fixed'] })
  await t.exception(() => population.register('dynamic'), /unknown population consumer/)
  population.register('fixed')
  await t.exception(() => population.register('fixed'), /duplicate population consumer/)
  population.insert('a')
  population.insert('b')
  await t.exception(() => population.insert('c'), /generation index backpressure/)
  await t.exception.all(() => population.page('fixed', Infinity), /population budget/)
})

test('completion scheduler coalesces a trigger and arms from completion', async (t) => {
  let release
  let calls = 0
  const first = new Promise(resolve => { release = resolve })
  const scheduler = new CompletionScheduler({
    name: 'test-pass',
    intervalMs: 60_000,
    run: async () => {
      calls++
      if (calls === 1) await first
      return { complete: true }
    }
  })
  scheduler.trigger()
  scheduler.trigger()
  t.is(calls, 0, 'task begins on the next microtask')
  await Promise.resolve()
  t.is(calls, 1)
  release()
  await new Promise(resolve => setTimeout(resolve, 10))
  t.is(calls, 2, 'one coalesced follow-up runs after completion')
  t.is(scheduler.snapshot().coalescedTriggers, 1)
  await scheduler.stop()
})

test('app registry pages retain update membership and fence deletion', (t) => {
  const registry = new AppRegistry(null, { requirePhysicalEnforcement: false })
  const firstKey = '11'.repeat(32)
  const secondKey = '22'.repeat(32)
  registry.set(firstKey, { appId: 'first' }, { persist: false })
  registry.set(secondKey, { appId: 'second' }, { persist: false })

  const first = registry.page('anchor', 1)
  t.alike(first.entries.map(item => item.key), [firstKey])
  registry.update(firstKey, { version: '2.0.0' }, { persist: false })
  const second = registry.page('anchor', 1)
  t.alike(second.entries.map(item => item.key), [secondKey], 'update retains the original membership generation')
  t.is(second.complete, true)

  registry.delete(secondKey, { persist: false })
  const next = registry.page('anchor', 4)
  t.alike(next.entries.map(item => item.key), [firstKey])
  t.is(next.complete, true)
})

test('app registry reserves fixed bounded consumers for accounting and dedup', (t) => {
  const registry = new AppRegistry(null, { requirePhysicalEnforcement: false })
  registry.set('55'.repeat(32), { appId: 'bounded' }, { persist: false })
  for (const consumer of ['storage-accounting', 'eviction', 'dedup-report', 'dedup-reclaim']) {
    t.is(registry.page(consumer, 1).entries.length, 1, `${consumer} can page the fixed population`)
    t.ok(registry.releasePopulationConsumer(consumer), `${consumer} can release its cursor`)
  }
})

test('app registry lease status publishes only complete high-water cycles', (t) => {
  const registry = new AppRegistry(null, { requirePhysicalEnforcement: false })
  registry.set('66'.repeat(32), { leaseManaged: true, retainUntil: 200 }, { persist: false })
  registry.set('77'.repeat(32), { leaseManaged: true, retainUntil: 50 }, { persist: false })

  const partial = registry.advanceLeaseStatusSnapshot(1, 100)
  t.is(partial.complete, false)
  t.alike(registry.leaseStatusSnapshot(), {
    activeLeases: 0,
    observedAt: null,
    completedAt: null,
    completedHighWater: 0
  }, 'partial work retains the prior complete aggregate')

  const complete = registry.advanceLeaseStatusSnapshot(1, 999)
  t.is(complete.complete, true)
  const snapshot = registry.leaseStatusSnapshot()
  t.is(snapshot.activeLeases, 1, 'the cycle uses its frozen observation time')
  t.is(snapshot.observedAt, 100)
  t.is(snapshot.completedHighWater, complete.completedHighWater)
  t.ok(Number.isSafeInteger(snapshot.completedAt))

  registry.releasePopulationConsumer('lease-api')
})

test('app registry catalog aggregates stay O(1) across mutations', (t) => {
  const registry = new AppRegistry(null, { requirePhysicalEnforcement: false })
  const app = '33'.repeat(32)
  const resource = '44'.repeat(32)
  registry.set(app, { type: 'app', appId: 'one' }, { persist: false })
  registry.set(resource, { type: 'drive', parentKey: app }, { persist: false })
  t.alike(registry.catalogStats(), {
    total: 2,
    anchored: 0,
    unanchored: 2,
    neverChecked: 2,
    apps: 1,
    drives: 0,
    resources: 1,
    datasets: 0,
    media: 0
  })

  registry.setAnchored(app, 1)
  registry.update(resource, { type: 'dataset', parentKey: null }, { persist: false })
  registry.recordAnchorCheck(resource)
  t.alike(registry.anchorStats(), { total: 2, anchored: 1, unanchored: 1, neverChecked: 0 })
  t.is(registry.catalogStats().resources, 0)
  t.is(registry.catalogStats().datasets, 1)

  registry.delete(app, { persist: false })
  t.alike(registry.catalogStats(), {
    total: 1,
    anchored: 0,
    unanchored: 1,
    neverChecked: 0,
    apps: 0,
    drives: 0,
    resources: 0,
    datasets: 1,
    media: 0
  })
})

test('completion scheduler drains before stop returns', async (t) => {
  let release
  let settled = false
  const gate = new Promise(resolve => { release = resolve })
  const scheduler = new CompletionScheduler({
    name: 'stop-drain',
    intervalMs: 60_000,
    run: async () => {
      await gate
      settled = true
      return { complete: true }
    }
  })
  scheduler.trigger()
  await Promise.resolve()
  const stopping = scheduler.stop()
  await Promise.resolve()
  t.is(settled, false, 'stop retains the active flight')
  release()
  await stopping
  t.is(settled, true, 'stop drains the active flight')
  t.is(scheduler.snapshot().stopping, true)
  t.is(scheduler.trigger(), false, 'post-stop work is fenced')
})
