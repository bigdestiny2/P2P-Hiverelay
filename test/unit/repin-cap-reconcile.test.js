// v0.8.12 — tests for AppLifecycle._reconcileSeedOptsOnRepin
//
// Covers the structural fix for ask (6) in
// docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md: when a publisher re-pins
// an already-seeded app with new opts, seedApp must not swallow them.
// Specifically tests the maxStorage cap reconciliation:
//   - new cap raised (or set where none was) → entry updated, retrigger
//   - new cap lowered → emit seed-cap-warning, keep old cap
//   - new cap unchanged (or both null) → no-op
//   - concurrent retrigger guard via entry._replicating
//   - drive missing / closed → don't retrigger
//
// AppLifecycle is built around a RelayNode. To keep these tests as
// isolated unit tests (no swarm, no real hyperdrive), we construct a
// thin fake node with just the surface AppLifecycle touches in the
// reconcile path.

import test from 'brittle'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

function fakeNode () {
  const registry = new AppRegistry(null)
  return {
    appRegistry: registry,
    seededApps: registry.apps,
    config: { custody: { defaultRetainMs: 0 } },
    seeder: { totalBytesStored: 0 },
    swarm: { keyPair: { publicKey: Buffer.alloc(32) } }
  }
}

function fakeDrive () {
  // Just enough surface to satisfy _reconcileSeedOptsOnRepin's checks
  // (drive presence + closed flag). _eagerReplicate is mocked out per
  // test so we don't need real hypercore behavior.
  return {
    closed: false,
    closing: false,
    discoveryKey: Buffer.alloc(32),
    version: 1
  }
}

function fakeEntry ({ maxStorage = null, anchored = false, drive = fakeDrive() } = {}) {
  return {
    drive,
    discoveryKey: drive.discoveryKey,
    startedAt: Date.now(),
    type: 'app',
    maxStorage,
    anchored,
    _replicating: false
  }
}

test('reconcile: same cap → no-op (no events, entry unchanged)', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-warning', e => events.push({ type: 'warn', ...e }))
  lifecycle.on('seed-cap-raised', e => events.push({ type: 'raised', ...e }))

  let replicateCalled = false
  lifecycle._eagerReplicate = async () => { replicateCalled = true }

  const entry = fakeEntry({ maxStorage: 1_000_000_000 })
  lifecycle._reconcileSeedOptsOnRepin('a'.repeat(64), entry, { maxStorage: 1_000_000_000 })

  t.is(events.length, 0, 'no events emitted for same cap')
  t.is(replicateCalled, false, 'eager replicate not retriggered')
  t.is(entry.maxStorage, 1_000_000_000, 'cap unchanged')
})

test('reconcile: both null → no-op', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-warning', e => events.push(e))
  lifecycle.on('seed-cap-raised', e => events.push(e))

  let replicateCalled = false
  lifecycle._eagerReplicate = async () => { replicateCalled = true }

  const entry = fakeEntry({ maxStorage: null })
  lifecycle._reconcileSeedOptsOnRepin('a'.repeat(64), entry, {})

  t.is(events.length, 0, 'no events emitted when neither side has a cap')
  t.is(replicateCalled, false, 'no replicate kicked off')
  t.is(entry.maxStorage, null, 'cap stays null')
})

test('reconcile: cap raised → entry updated + seed-cap-raised + replicate triggered', async (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-raised', e => events.push(e))

  let replicateArgs = null
  let replicateResolve
  const replicateP = new Promise(resolve => { replicateResolve = resolve })
  lifecycle._eagerReplicate = async (appKey, drive, opts, meta) => {
    replicateArgs = { appKey, drive, opts, meta }
    replicateResolve()
  }

  const appKey = 'b'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: 256 * 1024 * 1024 })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()
  entry.discoveryKey = entry.drive.discoveryKey

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 1024 * 1024 * 1024 })

  t.is(events.length, 1, 'seed-cap-raised emitted')
  t.is(events[0].appKey, appKey)
  t.is(events[0].oldCap, 256 * 1024 * 1024)
  t.is(events[0].newCap, 1024 * 1024 * 1024)
  t.is(entry.maxStorage, 1024 * 1024 * 1024, 'entry cap updated to new value')
  t.is(node.appRegistry.get(appKey).maxStorage, 1024 * 1024 * 1024, 'registry persists new cap')

  await replicateP
  t.ok(replicateArgs, 'eager replicate invoked')
  t.is(replicateArgs.appKey, appKey)
  t.is(replicateArgs.opts.maxStorage, 1024 * 1024 * 1024, 'replicate gets new cap')
  t.is(replicateArgs.meta.source, 'repin-cap-raised', 'meta tags the source')
})

test('reconcile: cap newly declared (was null) → treated as cap raised', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-raised', e => events.push(e))

  let replicateCalled = false
  lifecycle._eagerReplicate = async () => { replicateCalled = true }

  const appKey = 'c'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: null })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 500 * 1024 * 1024 })

  t.is(events.length, 1, 'seed-cap-raised emitted')
  t.is(events[0].oldCap, null, 'old cap reported as null')
  t.is(events[0].newCap, 500 * 1024 * 1024)
  t.is(entry.maxStorage, 500 * 1024 * 1024, 'entry now has cap')
  t.is(replicateCalled, true, 'replicate triggered')
})

test('reconcile: cap lowered → seed-cap-warning + keep old cap + no replicate', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const warnings = []
  lifecycle.on('seed-cap-warning', e => warnings.push(e))
  let replicateCalled = false
  lifecycle._eagerReplicate = async () => { replicateCalled = true }

  const appKey = 'd'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: 1024 * 1024 * 1024 })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 256 * 1024 * 1024 })

  t.is(warnings.length, 1, 'seed-cap-warning emitted')
  t.is(warnings[0].reason, 'cap-lowered-on-repin')
  t.is(warnings[0].oldCap, 1024 * 1024 * 1024)
  t.is(warnings[0].newCap, 256 * 1024 * 1024)
  t.is(entry.maxStorage, 1024 * 1024 * 1024, 'cap NOT lowered on entry (we keep the prior commitment)')
  t.is(replicateCalled, false, 'no replicate retriggered for cap lowered')
})

test('reconcile: cap raised while _replicating → entry updated but no second replicate spawned', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = 'e'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: 100_000_000 })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()
  entry._replicating = true // simulate an in-flight retrigger

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 500_000_000 })

  t.is(entry.maxStorage, 500_000_000, 'entry cap updated even while replicating')
  t.is(replicateCalls, 0, 'no second replicate spawned')
})

test('reconcile: cap raised but drive missing → entry updated but no replicate', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = 'f'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: 100_000_000 })
  const entry = node.appRegistry.get(appKey)
  // entry.drive intentionally undefined

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 500_000_000 })

  t.is(entry.maxStorage, 500_000_000, 'cap updated')
  t.is(replicateCalls, 0, 'no replicate when drive missing')
})

test('reconcile: cap raised but drive already closed → no replicate', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = '1'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: 100_000_000 })
  const entry = node.appRegistry.get(appKey)
  const closedDrive = fakeDrive()
  closedDrive.closed = true
  entry.drive = closedDrive

  lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 500_000_000 })

  t.is(entry.maxStorage, 500_000_000)
  t.is(replicateCalls, 0, 'no replicate when drive closed')
})

test('reconcile: invalid opts.maxStorage (NaN, negative, zero) treated as no-op when both equivalent to null', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-warning', e => events.push(e))
  lifecycle.on('seed-cap-raised', e => events.push(e))

  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const entry = fakeEntry({ maxStorage: null })
  lifecycle._reconcileSeedOptsOnRepin('2'.repeat(64), entry, { maxStorage: 0 })
  lifecycle._reconcileSeedOptsOnRepin('2'.repeat(64), entry, { maxStorage: -1 })
  lifecycle._reconcileSeedOptsOnRepin('2'.repeat(64), entry, { maxStorage: NaN })
  lifecycle._reconcileSeedOptsOnRepin('2'.repeat(64), entry, { maxStorage: undefined })

  t.is(events.length, 0, 'invalid caps yield no events (treated as null)')
  t.is(replicateCalls, 0)
})

test('AppRegistry: maxStorage round-trips through normalize + entries iteration', (t) => {
  const registry = new AppRegistry(null)

  registry.set('3'.repeat(64), { type: 'app', maxStorage: 1024 * 1024 * 1024 })
  registry.set('4'.repeat(64), { type: 'app', maxStorage: null })
  registry.set('5'.repeat(64), { type: 'app' /* no maxStorage */ })
  registry.set('6'.repeat(64), { type: 'app', maxStorage: 0 }) // should normalize to null
  registry.set('7'.repeat(64), { type: 'app', maxStorage: -5 }) // negative → null

  t.is(registry.get('3'.repeat(64)).maxStorage, 1024 * 1024 * 1024)
  t.is(registry.get('4'.repeat(64)).maxStorage, null)
  t.is(registry.get('5'.repeat(64)).maxStorage, null)
  t.is(registry.get('6'.repeat(64)).maxStorage, null, '0 normalized to null')
  t.is(registry.get('7'.repeat(64)).maxStorage, null, 'negative normalized to null')
})

test('AppRegistry.update preserves maxStorage when not in updates', (t) => {
  const registry = new AppRegistry(null)
  const key = '8'.repeat(64)
  registry.set(key, { type: 'app', appId: 'x', maxStorage: 500_000_000 })

  registry.update(key, { version: '2.0.0' })

  t.is(registry.get(key).maxStorage, 500_000_000, 'maxStorage preserved through unrelated update')
  t.is(registry.get(key).version, '2.0.0', 'update applied')
})

test('AppRegistry.update can change maxStorage', (t) => {
  const registry = new AppRegistry(null)
  const key = '9'.repeat(64)
  registry.set(key, { type: 'app', maxStorage: 100_000 })

  registry.update(key, { maxStorage: 999_999_999 })

  t.is(registry.get(key).maxStorage, 999_999_999, 'maxStorage updated via update()')
})
