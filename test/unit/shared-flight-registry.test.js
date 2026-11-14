import test from 'brittle'
import {
  SharedFlightRegistry,
  closeSharedDriveEntity,
  parseSharedFlightDeadline,
  sharedBlobHas,
  sharedGetBlobs,
  sharedOperationFlights
} from '../../packages/core/core/shared-flight-registry.js'

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  return { promise, resolve, reject }
}

test('shared-flight deadlines reject malformed values and clamp valid maxima', async (t) => {
  t.is(parseSharedFlightDeadline(undefined, 5, 30), 5)
  t.is(parseSharedFlightDeadline(100, 5, 30), 30)
  for (const value of ['5', 0, -1, 1.2, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await t.exception.all(
      () => parseSharedFlightDeadline(value, 5, 30),
      /positive safe integer/
    )
  }
})

test('first timeout orphans one raw call and thousands of retries cannot restart or attach', async (t) => {
  const registry = new SharedFlightRegistry()
  const entity = {}
  const owner = {}
  const raw = deferred()
  let starts = 0
  await t.exception(
    registry.run(entity, 'stuck', () => {
      starts++
      return raw.promise
    }, { owner, timeoutMs: 1 }),
    { code: 'SHARED_FLIGHT_TIMEOUT' }
  )

  const retries = []
  for (let i = 0; i < 2_000; i++) {
    retries.push(registry.run(entity, 'stuck', () => {
      starts++
      return raw.promise
    }, { owner, timeoutMs: 1 }).catch(err => err.code))
  }
  const codes = await Promise.all(retries)
  t.ok(codes.every(code => code === 'SHARED_FLIGHT_ORPHANED'))
  t.is(starts, 1)
  t.is(registry.getStats().pending, 1)
  t.is(registry.getStats().waiters, 0)
  t.is(registry.getStats().orphanedPending, 1)

  raw.resolve('settled')
  await registry.drainOwner(owner, { timeoutMs: 100 })
  t.is(registry.getStats().pending, 0)
  t.is(registry.getStats(owner).owner.activeFlights, 0)
})

test('waiter, owner and process caps reject before starting extra raw work', async (t) => {
  const registry = new SharedFlightRegistry({
    maxWaiters: 2,
    maxOwnerFlights: 1,
    maxProcessFlights: 2
  })
  const owner = {}
  const rawA = deferred()
  const rawB = deferred()
  const a1 = registry.run({}, 'a', () => rawA.promise, { owner, timeoutMs: 1000 })
  // Use the same physical entity for waiter-cap coverage.
  const entity = {}
  const b1 = registry.run(entity, 'b', () => rawB.promise, { owner: entity, timeoutMs: 1000 })
  const b2 = registry.run(entity, 'b', () => rawB.promise, { owner: entity, timeoutMs: 1000 })
  await t.exception(
    registry.run(entity, 'b', () => rawB.promise, { owner: entity, timeoutMs: 1000 }),
    { code: 'SHARED_FLIGHT_BUSY', details: { reason: 'waiter limit reached' } }
  )
  await t.exception(
    registry.run({}, 'owner-overflow', () => Promise.resolve(), { owner, timeoutMs: 1000 }),
    { code: 'SHARED_FLIGHT_BUSY', details: { reason: 'process flight limit reached' } }
  )
  t.is(registry.getStats().pending, 2)
  rawA.resolve('a')
  rawB.resolve('b')
  t.is(await a1, 'a')
  t.alike(await Promise.all([b1, b2]), ['b', 'b'])

  const ownerRegistry = new SharedFlightRegistry({ maxOwnerFlights: 1, maxProcessFlights: 2 })
  const first = deferred()
  const firstResult = ownerRegistry.run({}, 'first', () => first.promise, { owner, timeoutMs: 1000 })
  await t.exception(
    ownerRegistry.run({}, 'second', () => Promise.resolve(), { owner, timeoutMs: 1000 }),
    { code: 'SHARED_FLIGHT_BUSY', details: { reason: 'owner flight limit reached' } }
  )
  first.resolve(true)
  t.ok(await firstResult)
})

test('owner generation invalidation suppresses late mutation but permits one shared new-generation attach', async (t) => {
  const registry = new SharedFlightRegistry()
  const entity = {}
  const owner = {}
  const raw = deferred()
  let starts = 0
  const stale = registry.run(entity, 'generation', () => {
    starts++
    return raw.promise
  }, { owner, timeoutMs: 1000 })
  registry.invalidateOwner(owner)
  const current = registry.run(entity, 'generation', () => {
    starts++
    return raw.promise
  }, { owner, timeoutMs: 1000 })
  raw.resolve(42)
  await t.exception(stale, { code: 'SHARED_FLIGHT_OWNER_INVALIDATED' })
  t.is(await current, 42)
  t.is(starts, 1)
  t.is(registry.getStats().lateSuppressed, 1)
})

test('proved close completion releases exact entity identity and suppresses raw late settlement', async (t) => {
  const registry = new SharedFlightRegistry()
  const entity = {}
  const raw = deferred()
  let starts = 0
  const old = registry.run(entity, 'close', () => {
    starts++
    return raw.promise
  }, { timeoutMs: 1000 })
  t.is(registry.closeEntity(entity), 1)
  await t.exception(old, { code: 'SHARED_FLIGHT_ENTITY_CLOSED' })

  const next = registry.run(entity, 'close', () => {
    starts++
    return Promise.resolve('new incarnation')
  }, { timeoutMs: 1000 })
  t.is(await next, 'new incarnation')
  t.is(starts, 2)
  raw.resolve('late')
  await new Promise(resolve => setImmediate(resolve))
  t.is(registry.getStats().lateSuppressed, 1)
  t.is(registry.getStats().pending, 0)
})

test('getBlobs and exact-range composite has dedupe across purposes sharing a physical core', async (t) => {
  const physicalCore = {}
  const blobCore = { hasCalls: 0, has: null }
  const blobsRaw = deferred()
  const shortRange = deferred()
  const longRange = deferred()
  const ranges = []
  blobCore.has = (start, length) => {
    blobCore.hasCalls++
    ranges.push([start, length])
    return length === 10 ? shortRange.promise : longRange.promise
  }
  let getBlobsCalls = 0
  const driveA = {
    core: physicalCore,
    getBlobs () {
      getBlobsCalls++
      return blobsRaw.promise
    }
  }
  const driveB = {
    core: physicalCore,
    getBlobs () {
      getBlobsCalls++
      return blobsRaw.promise
    }
  }
  const purposeA = sharedGetBlobs(driveA, { owner: {}, timeoutMs: 1000 })
  const purposeB = sharedGetBlobs(driveB, { owner: {}, timeoutMs: 1000 })
  blobsRaw.resolve({ core: blobCore })
  t.is((await purposeA).core, blobCore)
  t.is((await purposeB).core, blobCore)
  t.is(getBlobsCalls, 1)

  const hasA = sharedBlobHas(blobCore, 0, 10, { owner: {}, timeoutMs: 1000 })
  const hasSame = sharedBlobHas(blobCore, 0, 10, { owner: {}, timeoutMs: 1000 })
  const hasB = sharedBlobHas(blobCore, 0, 20, { owner: {}, timeoutMs: 1000 })
  shortRange.resolve(true)
  longRange.resolve(false)
  t.ok(await hasA)
  t.ok(await hasSame, 'the exact same range attaches to one raw flight')
  t.not(await hasB, 'a longer unverified range cannot inherit a shorter true result')
  t.is(blobCore.hasCalls, 2)
  t.alike(ranges, [[0, 10], [0, 20]])

  for (const [start, length] of [[-1, 1], [0.5, 1], [0, -1], [0, 0.5], [Number.MAX_SAFE_INTEGER, 1]]) {
    await t.exception.all(
      () => sharedBlobHas(blobCore, start, length),
      /bounded nonnegative safe integers/
    )
  }

  closeSharedDriveEntity(driveA, 'test close completion')
  t.is(sharedOperationFlights.getStats().pending, 0)
})
