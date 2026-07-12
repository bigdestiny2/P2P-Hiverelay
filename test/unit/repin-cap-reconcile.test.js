// v0.8.12 — tests for AppLifecycle._reconcileSeedOptsOnRepin
//
// Covers the structural fix for ask (6) in
// docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md: when a publisher re-pins
// an already-seeded app with new opts, seedApp must not swallow them.
// Specifically tests the maxStorage cap reconciliation:
//   - finite cap raised → admission-gated entry update + retrigger
//   - new cap set where none was stored → fail closed (unknown baseline)
//   - omitted cap with a finite prior cap → no-op
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

function fakeNode ({ admission = { allowed: true, reason: null, availableBytes: Number.MAX_SAFE_INTEGER } } = {}) {
  const registry = new AppRegistry(null)
  const node = {
    appRegistry: registry,
    seededApps: registry.apps,
    config: { custody: { defaultRetainMs: 0 } },
    seeder: { totalBytesStored: 0 },
    swarm: { keyPair: { publicKey: Buffer.alloc(32) } },
    _admissionCalls: []
  }
  node._storageAdmission = (additionalBytes) => {
    node._admissionCalls.push(additionalBytes)
    return typeof admission === 'function' ? admission(additionalBytes) : admission
  }
  return node
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

test('reconcile: omitted cap preserves an existing finite cap', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)
  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = '7'.repeat(64)
  const oldCap = 500_000_000
  node.appRegistry.set(appKey, { type: 'app', maxStorage: oldCap })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  const result = lifecycle._reconcileSeedOptsOnRepin(appKey, entry, {})

  t.is(result.ok, true)
  t.is(result.changed, false)
  t.is(result.reason, 'cap-omitted-on-repin')
  t.is(entry.maxStorage, oldCap)
  t.alike(node._admissionCalls, [], 'no admission needed when capacity does not grow')
  t.is(replicateCalls, 0)
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

  const result = lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 1024 * 1024 * 1024 })

  t.is(events.length, 1, 'seed-cap-raised emitted')
  t.is(events[0].appKey, appKey)
  t.is(events[0].oldCap, 256 * 1024 * 1024)
  t.is(events[0].newCap, 1024 * 1024 * 1024)
  t.is(entry.maxStorage, 1024 * 1024 * 1024, 'entry cap updated to new value')
  t.is(node.appRegistry.get(appKey).maxStorage, 1024 * 1024 * 1024, 'registry persists new cap')
  t.alike(node._admissionCalls, [768 * 1024 * 1024], 'only incremental worst-case growth is admitted')
  t.is(result.ok, true)
  t.is(result.changed, true)
  t.is(result.incrementalBytes, 768 * 1024 * 1024)
  t.is(result.replicationStarted, true)

  await replicateP
  t.ok(replicateArgs, 'eager replicate invoked')
  t.is(replicateArgs.appKey, appKey)
  t.is(replicateArgs.opts.maxStorage, 1024 * 1024 * 1024, 'replicate gets new cap')
  t.is(replicateArgs.meta.source, 'repin-cap-raised', 'meta tags the source')
})

test('reconcile: cap newly declared with an unknown old baseline fails closed', (t) => {
  const node = fakeNode()
  const lifecycle = new AppLifecycle(node)

  const events = []
  lifecycle.on('seed-cap-warning', e => events.push(e))

  let replicateCalled = false
  lifecycle._eagerReplicate = async () => { replicateCalled = true }

  const appKey = 'c'.repeat(64)
  node.appRegistry.set(appKey, { type: 'app', maxStorage: null })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  const result = lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: 500 * 1024 * 1024 })

  t.is(events.length, 1, 'non-success warning emitted')
  t.is(events[0].reason, 'cap-baseline-unknown-on-repin')
  t.is(events[0].oldCap, null, 'old cap reported as null')
  t.is(events[0].newCap, 500 * 1024 * 1024)
  t.is(entry.maxStorage, null, 'entry remains unchanged')
  t.is(node.appRegistry.get(appKey).maxStorage, null, 'registry remains unchanged')
  t.is(replicateCalled, false, 'replication is not triggered')
  t.is(node._admissionCalls.length, 0, 'unknown baseline is rejected before pretending it is zero')
  t.is(result.ok, false)
  t.is(result.changed, false)
  t.is(result.incrementalBytes, null)
})

test('reconcile: over-cap admission blocks cap-up before mutation or replication', (t) => {
  const node = fakeNode({
    admission: { allowed: false, reason: 'storage-cap-reached', availableBytes: 0 }
  })
  const lifecycle = new AppLifecycle(node)
  const warnings = []
  lifecycle.on('seed-cap-warning', e => warnings.push(e))
  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = '0'.repeat(64)
  const oldCap = 256 * 1024 * 1024
  const newCap = 1024 * 1024 * 1024
  node.appRegistry.set(appKey, { type: 'app', maxStorage: oldCap })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  const result = lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: newCap })

  t.alike(node._admissionCalls, [newCap - oldCap])
  t.is(result.ok, false)
  t.is(result.reason, 'cap-raise-storage-admission-blocked')
  t.is(result.admissionReason, 'storage-cap-reached')
  t.is(entry.maxStorage, oldCap, 'entry cap is not mutated')
  t.is(node.appRegistry.get(appKey).maxStorage, oldCap, 'registry cap is not mutated')
  t.is(replicateCalls, 0, 'replication is not triggered')
  t.is(warnings.length, 1)
  t.is(warnings[0].incrementalBytes, newCap - oldCap)
})

test('reconcile: reached physical reserve blocks cap-up before mutation or replication', (t) => {
  const node = fakeNode({
    admission: { allowed: false, reason: 'storage-reserve-reached', availableBytes: 0 }
  })
  const lifecycle = new AppLifecycle(node)
  let replicateCalls = 0
  lifecycle._eagerReplicate = async () => { replicateCalls++ }

  const appKey = 'a'.repeat(64)
  const oldCap = 100_000_000
  const newCap = 500_000_000
  node.appRegistry.set(appKey, { type: 'app', maxStorage: oldCap })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()

  const result = lifecycle._reconcileSeedOptsOnRepin(appKey, entry, { maxStorage: newCap })

  t.is(result.ok, false)
  t.is(result.admissionReason, 'storage-reserve-reached')
  t.is(entry.maxStorage, oldCap)
  t.is(node.appRegistry.get(appKey).maxStorage, oldCap)
  t.is(replicateCalls, 0)
})

test('seedApp: blocked cap-up is surfaced in the alreadySeeded result', async (t) => {
  const node = fakeNode({
    admission: { allowed: false, reason: 'storage-cap-reached', availableBytes: 0 }
  })
  const lifecycle = new AppLifecycle(node)
  const appKey = 'b'.repeat(64)
  const oldCap = 100_000_000
  node.appRegistry.set(appKey, { type: 'app', maxStorage: oldCap })
  const entry = node.appRegistry.get(appKey)
  entry.drive = fakeDrive()
  entry.discoveryKey = entry.drive.discoveryKey

  const result = await lifecycle.seedApp(appKey, { maxStorage: 500_000_000 })

  t.is(result.alreadySeeded, true)
  t.is(result.repin.ok, false)
  t.is(result.repin.reason, 'cap-raise-storage-admission-blocked')
  t.is(result.repin.admissionReason, 'storage-cap-reached')
  t.is(entry.maxStorage, oldCap)
})

test('recovery placeholder: cap-up is admitted before drive adoption or registry mutation', async (t) => {
  const node = fakeNode({
    admission: { allowed: false, reason: 'storage-cap-reached', availableBytes: 0 }
  })
  const appKey = '6'.repeat(64)
  const oldCap = 100_000_000
  const newCap = 500_000_000
  node.appRegistry.set(appKey, {
    type: 'app',
    discoveryKey: null,
    maxStorage: oldCap
  })
  let storeTouched = false
  node.store = {
    session () {
      storeTouched = true
      throw new Error('must not adopt a drive before admission')
    }
  }
  const lifecycle = new AppLifecycle(node)

  let error = null
  try {
    await lifecycle._seedAppInner(appKey, { maxStorage: newCap }, 'app', null, null, 'public')
  } catch (err) {
    error = err
  }

  t.ok(error)
  t.is(error.code, 'STORAGE_CAP_REPIN_BLOCKED')
  t.is(error.repin.reason, 'cap-raise-storage-admission-blocked')
  t.is(error.repin.admissionReason, 'storage-cap-reached')
  t.alike(node._admissionCalls, [newCap - oldCap])
  t.is(node.appRegistry.get(appKey).maxStorage, oldCap, 'persisted cap remains unchanged')
  t.is(storeTouched, false, 'Corestore is untouched when incremental admission fails')
})

test('recovery placeholder: persisted cap can reopen without new admission', (t) => {
  const node = fakeNode({
    admission: { allowed: false, reason: 'storage-cap-reached', availableBytes: 0 }
  })
  const lifecycle = new AppLifecycle(node)
  const oldCap = 500_000_000
  const entry = fakeEntry({ maxStorage: oldCap })
  entry.discoveryKey = null

  const same = lifecycle._preflightRecoveredEntryCap('5'.repeat(64), entry, { maxStorage: oldCap })
  const omitted = lifecycle._preflightRecoveredEntryCap('5'.repeat(64), entry, {})

  t.is(same.ok, true)
  t.is(same.changed, false)
  t.is(same.effectiveCap, oldCap)
  t.is(omitted.ok, true)
  t.is(omitted.changed, false)
  t.is(omitted.effectiveCap, oldCap)
  t.alike(node._admissionCalls, [], 'restart recovery consumes no new capacity')
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
