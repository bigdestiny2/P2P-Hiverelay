/**
 * Sticky operator tombstones + tombstone-aware acceptance (v0.24.7 port).
 *
 * Production bug (2026-10-27, v0.24.6): an operator removed ~400 apps
 * fleet-wide (manual purge: unseed + purge + tombstone), then flipped the
 * fleet back to open accept mode. Within minutes 97 of them were seeded
 * again: the persistent seed-request log replay and live seed requests never
 * checked the tombstone, and the one gate that did (replication repair)
 * clears it whenever the network is under the replica floor — which a
 * fleet-wide removal always is. main carries the same paths.
 *
 * Now every acceptance path refuses a tombstoned app, and tombstones carry
 * a kind: operator removals are sticky (only an explicit operator seed
 * lifts them), eviction tombstones keep the under-floor re-adoption. On
 * main the kind also has to survive the Hyperbee journal (storageDeleted
 * rows carry evictionKind) and the evicted.json → Bee migration, which must
 * accept the 0.24.7 sidecar format.
 *
 * RelayNode cases use a constructed (not started) node with the
 * network-facing pieces stubbed. The real RelayNode.seedApp runs (so its
 * tombstone backstop is exercised); only appLifecycle.seedApp — the
 * drive/swarm work — is stubbed.
 */

import test from 'brittle'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { mkdirSync } from 'fs'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { openCorestore } from '../../packages/core/core/persistence/storage-root-restore.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { AppRegistry, TOMBSTONE_EVICTION, TOMBSTONE_OPERATOR } from 'p2p-hiverelay/core/app-registry.js'
import { runOperatorSeedAction } from 'p2p-hiverelay/core/relay-node/api-seed-publish.js'
import { EvictionManager } from 'p2p-hiverelay/core/relay-node/eviction.js'

const BOUND = 1024 * 1024

function tmpStorage () {
  const storage = path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex'))
  mkdirSync(storage, { recursive: true })
  return storage
}

function hexKey () {
  return randomBytes(32).toString('hex')
}

async function openBeeRegistry (dir) {
  const store = openCorestore(dir)
  await store.ready()
  const registry = new AppRegistry(dir, { store })
  await registry.load()
  return { store, registry }
}

function makeNode (t, { acceptMode = 'open' } = {}) {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false, enableServices: false })
  const realStore = node.store
  t.teardown(async () => {
    try { await realStore.close() } catch (_) {}
  })
  node.config.acceptMode = acceptMode
  node.config.enableSeeding = true
  node.config.targetReplicaFloor = 2
  node._storageAdmission = () => ({ allowed: true, availableBytes: 1024 * BOUND })
  const myPubkey = randomBytes(32)
  node.swarm = { keyPair: { publicKey: myPubkey } }

  const sent = { seeded: [], accepts: [], denies: [], skipped: [], cleared: [] }
  node.appLifecycle.seedApp = async (key) => {
    sent.seeded.push(key)
    node.appRegistry.apps.set(key, { appKey: key, durability: 0 })
    return { appKey: key }
  }
  node.seeder = { cores: new Map(), totalBytesStored: 0, seedCore: async () => {} }
  node._seedProtocol = {
    acceptSeedRequest (appKey) { sent.accepts.push(b4a.toString(appKey, 'hex')) },
    denySeedRequest (channel, appKey, reasonCode, detail) { sent.denies.push({ reasonCode, detail }) }
  }
  node.on('tombstone-skipped', (ev) => sent.skipped.push(ev))
  node.on('tombstone-cleared', (ev) => sent.cleared.push(ev))
  return { node, sent, myPubkeyHex: b4a.toString(myPubkey, 'hex') }
}

// Persistent seed-request log stub: `accepted` lists the app keys this relay
// already holds an acceptance record for (unseed leaves it in the log).
function fakeSeedingRegistry (requests, { accepted = [], myPubkeyHex }) {
  const acceptances = []
  return {
    acceptances,
    async getActiveRequests () { return requests },
    async getRelaysForApp (appKey) {
      return accepted.includes(appKey) ? [{ relayPubkey: myPubkeyHex }] : []
    },
    async recordAcceptance (appKey) { acceptances.push(appKey) }
  }
}

function registryRequest (appKey) {
  return {
    appKey,
    publisherPubkey: hexKey(),
    replicationFactor: 3,
    maxStorageBytes: BOUND,
    privacyTier: 'public',
    contentType: 'app'
  }
}

function seedRequest (appKey) {
  return {
    appKey: b4a.from(appKey, 'hex'),
    publisherPubkey: randomBytes(32),
    discoveryKeys: [],
    replicationFactor: 2,
    maxStorageBytes: BOUND,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0
  }
}

function repairRequest (appKey) {
  return { appKey, publisherPubkey: hexKey(), privacyTier: 'public', contentType: 'app', maxStorageBytes: BOUND }
}

const UNDER_FLOOR = { current: 0, target: 3, relays: [] }

// ─── AppRegistry: kinds + evicted.json compatibility (sidecar mode) ─

test('tombstones: a legacy evicted.json ({appKey: timestampMs}) loads as eviction tombstones', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-legacy-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const a = 'aa'.repeat(32)
  const b = 'bb'.repeat(32)
  await writeFile(path.join(dir, 'evicted.json'), JSON.stringify({ [a]: 1000, [b]: 2000 }))

  const reg = new AppRegistry(dir)
  await reg.load()
  t.ok(reg.isEvicted(a) && reg.isEvicted(b), 'legacy tombstones loaded')
  t.alike(reg.getTombstone(a), { at: 1000, kind: TOMBSTONE_EVICTION }, 'legacy entry is an eviction tombstone')
  t.ok(await reg.clearEvicted(b), 'legacy (eviction) tombstone still clears under the floor rule')
})

test('tombstones: operator kind round-trips; eviction entries keep the legacy number format', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-kinds-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const op = 'cc'.repeat(32)
  const ev = 'dd'.repeat(32)
  const reg1 = new AppRegistry(dir)
  await reg1.markEvicted(op, 5000, { kind: TOMBSTONE_OPERATOR })
  await reg1.markEvicted(ev, 6000)

  const raw = JSON.parse(await readFile(path.join(dir, 'evicted.json'), 'utf8'))
  t.is(raw[ev], 6000, 'eviction tombstone written as a bare timestamp (downgrade-safe)')
  t.alike(raw[op], { at: 5000, kind: TOMBSTONE_OPERATOR }, 'operator tombstone written with its kind')

  const reg2 = new AppRegistry(dir)
  await reg2.load()
  t.alike(reg2.getTombstone(op), { at: 5000, kind: TOMBSTONE_OPERATOR }, 'operator kind survives reload')
  t.alike(reg2.getTombstone(ev), { at: 6000, kind: TOMBSTONE_EVICTION }, 'eviction kind survives reload')
})

test('tombstones: an operator tombstone only clears with an explicit operator action', async (t) => {
  const reg = new AppRegistry(null)
  const k = 'ee'.repeat(32)
  await reg.markEvicted(k, 1, { kind: TOMBSTONE_OPERATOR })
  t.is(await reg.clearEvicted(k), false, 'plain clear (the under-floor rule) refused')
  t.ok(reg.isEvicted(k), 'still tombstoned')
  await reg.markEvicted(k, 2) // a later automatic shed must not downgrade it
  t.is(reg.getTombstone(k).kind, TOMBSTONE_OPERATOR, 'never downgraded to eviction')
  t.is(await reg.clearEvicted(k, { operator: true }), true, 'operator clear lifts it')
  t.absent(reg.isEvicted(k), 'gone')
})

test('tombstones: the size bound sheds old eviction tombstones, never operator ones', async (t) => {
  const reg = new AppRegistry(null)
  const op = 'ff'.repeat(32)
  await reg.markEvicted(op, 1, { kind: TOMBSTONE_OPERATOR }) // the oldest entry
  for (let i = 1; i <= 5000; i++) await reg.markEvicted(i.toString(16).padStart(64, '0'), i + 1)
  t.is(reg.evicted.size, 5000, 'bounded')
  t.ok(reg.isEvicted(op), 'oldest entry is an operator removal and survives the bound')
  t.absent(reg.isEvicted((1).toString(16).padStart(64, '0')), 'oldest eviction tombstone fell off instead')
})

// ─── AppRegistry: Hyperbee journal ──────────────────────────────────

test('tombstones (bee): a 0.24.7 evicted.json migrates into the journal with its kinds', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-bee-migrate-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const op = 'ab'.repeat(32)
  const ev = 'cd'.repeat(32)
  await writeFile(path.join(dir, 'evicted.json'), JSON.stringify({
    [op]: { at: 1_700_000_000_000, kind: 'operator' },
    [ev]: 1_700_000_000_001
  }))

  {
    const { store, registry } = await openBeeRegistry(dir)
    t.alike(registry.getTombstone(op), { at: 1_700_000_000_000, kind: TOMBSTONE_OPERATOR }, 'operator row migrated')
    t.alike(registry.getTombstone(ev), { at: 1_700_000_000_001, kind: TOMBSTONE_EVICTION }, 'legacy row migrated')
    await store.close()
  }
  {
    const { store, registry } = await openBeeRegistry(dir)
    t.is(registry.getTombstone(op).kind, TOMBSTONE_OPERATOR, 'kind survives a journal reload')
    t.is(registry.getTombstone(ev).kind, TOMBSTONE_EVICTION, 'eviction kind too')
    await store.close()
  }
})

test('tombstones (bee): an operator tombstone is durable and only an operator clear lifts it', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-bee-op-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const op = 'ef'.repeat(32)
  {
    const { store, registry } = await openBeeRegistry(dir)
    await registry.markEvicted(op, 1_700_000_000_000)
    await registry.markEvicted(op, 1_700_000_000_000, { kind: TOMBSTONE_OPERATOR }) // upgrade, same timestamp
    t.is(registry.getTombstone(op).kind, TOMBSTONE_OPERATOR, 'upgraded in memory')
    t.is(await registry.clearEvicted(op), false, 'under-floor clear refused')
    await store.close()
  }
  {
    const { store, registry } = await openBeeRegistry(dir)
    t.is(registry.getTombstone(op).kind, TOMBSTONE_OPERATOR, 'operator kind persisted in the journal row')
    t.is(await registry.clearEvicted(op, { operator: true }), true, 'operator clear lifts it')
    await store.close()
  }
  {
    const { store, registry } = await openBeeRegistry(dir)
    t.absent(registry.isEvicted(op), 'lift persisted')
    await store.close()
  }
})

// ─── Boot replay of the persistent seed-request log ─────────────────

test('open mode: registry-log replay skips tombstoned apps (re-seed-after-restart and fresh-accept branches)', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  const replayed = hexKey() // this relay accepted it before the removal
  const fresh = hexKey() // never accepted here
  const evicted = hexKey()
  const control = hexKey()
  await node.appRegistry.markEvicted(replayed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  await node.appRegistry.markEvicted(fresh, Date.now(), { kind: TOMBSTONE_OPERATOR })
  await node.appRegistry.markEvicted(evicted, Date.now())
  node.seedingRegistry = fakeSeedingRegistry(
    [replayed, fresh, evicted, control].map(registryRequest),
    { accepted: [replayed], myPubkeyHex }
  )

  await node._scanRegistry()

  t.alike(sent.seeded, [control], 'only the untombstoned request is seeded')
  t.alike(node.seedingRegistry.acceptances, [control], 'no acceptance recorded for tombstoned apps')
  t.is(node._pendingRequests.size, 0, 'nothing queued either')
  const skipped = sent.skipped.filter(s => s.source === 'registry-scan').map(s => s.appKey).sort()
  t.alike(skipped, [replayed, fresh, evicted].sort(), 'each skip is logged with its source')

  await node._scanRegistry()
  t.is(sent.skipped.length, 3, 'repeat scans do not re-log the same skip (rate-limited)')
})

test('review mode: registry-log replay does not re-queue a tombstoned app', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t, { acceptMode: 'review' })
  const removed = hexKey()
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  node.seedingRegistry = fakeSeedingRegistry([registryRequest(removed)], { myPubkeyHex })

  await node._scanRegistry()

  t.is(node._pendingRequests.size, 0, 'not queued for approval')
  t.is(sent.seeded.length, 0, 'not seeded')
})

// ─── Live seed requests ─────────────────────────────────────────────

test('open mode: a live seed request for a tombstoned app is denied, not seeded', async (t) => {
  const { node, sent } = makeNode(t)
  const removed = hexKey()
  const evicted = hexKey()
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  await node.appRegistry.markEvicted(evicted, Date.now())

  await node._onSeedRequest(seedRequest(removed), {})
  await node._onSeedRequest(seedRequest(evicted), {})

  t.is(sent.accepts.length, 0, 'no accept sent')
  t.is(sent.seeded.length, 0, 'nothing seeded')
  t.alike(sent.denies.map(d => d.reasonCode), ['tombstoned:operator', 'tombstoned:eviction'], 'denied with the tombstone reason')
  t.alike(sent.skipped.map(s => s.source), ['seed-request', 'seed-request'], 'skips logged')
})

test('seedApp backstop: a tombstoned app is refused; an explicit operator seed lifts the tombstone', async (t) => {
  const { node, sent } = makeNode(t)
  const removed = hexKey()
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  await t.exception(() => node.seedApp(removed, { maxStorage: BOUND }), /TOMBSTONED/, 'automatic callers get TOMBSTONED')
  t.is(sent.seeded.length, 0, 'nothing seeded')

  const out = await runOperatorSeedAction({ body: { appKey: removed, opts: { maxStorage: BOUND } }, node })
  t.ok(out.ok, 'operator POST /seed succeeds')
  t.alike(sent.seeded, [removed], 'operator seed re-adopts the app')
  t.absent(node.appRegistry.isEvicted(removed), 'tombstone lifted')
  t.alike(sent.cleared, [{ appKey: removed, kind: TOMBSTONE_OPERATOR }], 'lift is logged')
})

// ─── Replication repair: operator vs eviction tombstones ────────────

test('repair: an operator tombstone survives under-floor repair', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const removed = hexKey()
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  t.is(await node._attemptReplicationRepair(repairRequest(removed), UNDER_FLOOR), false, 'not repaired')
  t.is(sent.seeded.length, 0, 'not seeded')
  t.is(node.appRegistry.getTombstone(removed).kind, TOMBSTONE_OPERATOR, 'operator tombstone intact')
  t.is(sent.skipped[0] && sent.skipped[0].source, 'replication-repair', 'skip logged')
})

test('repair: manualPurge on an unheld key (e.g. a pre-0.24.7 eviction tombstone) makes it sticky', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const legacy = hexKey()
  await node.appRegistry.markEvicted(legacy, 1000) // what a v0.24.6 removal left behind

  const out = await node.manualPurge(legacy)
  t.alike(out, { appKey: legacy, bytes: 0, method: 'tombstone-only' }, 'nothing to purge, tombstone recorded')
  t.is(node.appRegistry.getTombstone(legacy).kind, TOMBSTONE_OPERATOR, 'upgraded to an operator tombstone')

  t.is(await node._attemptReplicationRepair(repairRequest(legacy), UNDER_FLOOR), false, 'under-floor repair refuses')
  t.ok(node.appRegistry.isEvicted(legacy), 'tombstone survives')
  t.is(sent.seeded.length, 0, 'never re-seeded')
})

test('repair: review mode does not re-queue an operator-removed app', async (t) => {
  const { node, myPubkeyHex } = makeNode(t, { acceptMode: 'review' })
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const removed = hexKey()
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  await node._attemptReplicationRepair(repairRequest(removed), UNDER_FLOOR)
  t.is(node._pendingRequests.size, 0, 'not queued')
})

test('repair: an eviction tombstone is still re-adopted under the floor', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const shed = hexKey()
  await node.appRegistry.markEvicted(shed, Date.now())

  t.is(await node._attemptReplicationRepair(repairRequest(shed), UNDER_FLOOR), true, 'repaired')
  t.alike(sent.seeded, [shed], 're-seeded')
  t.absent(node.appRegistry.isEvicted(shed), 'eviction tombstone cleared (we are needed again)')
  t.alike(node.seedingRegistry.acceptances, [shed], 'acceptance recorded')
})

test('repair: an eviction tombstone at or above the floor is kept', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const shed = hexKey()
  await node.appRegistry.markEvicted(shed, Date.now())

  const atFloor = { current: 2, target: 3, relays: [{ relayPubkey: hexKey() }, { relayPubkey: hexKey() }] }
  t.is(await node._attemptReplicationRepair(repairRequest(shed), atFloor), false, 'not repaired')
  t.is(sent.seeded.length, 0, 'not seeded')
  t.ok(node.appRegistry.isEvicted(shed), 'tombstone kept')
})

// ─── Live: the boot replay resuming long after boot ─────────────────

test('live: an eviction that unwedges the seed lane lets nothing removed since boot re-seed', async (t) => {
  // Production sequence (v0.24.6, review mode, no restart): one reseed is
  // stuck in _seedAppInner holding the seed admission lane (a drive open
  // that never settles), so the boot replay loop waits behind it. An
  // eviction sweep evicts that app, its purge fails the stuck open, and the
  // loop and any seed still queued for the lane run in the same tick,
  // including apps removed or evicted since boot. On main a queued seed
  // gives up after seedAdmissionTimeoutMs, so only the replay loop waits
  // for hours; a seed queued inside that window still needs the re-check.
  const { node, sent, myPubkeyHex } = makeNode(t, { acceptMode: 'review' })
  const lc = node.appLifecycle
  delete lc.seedApp // the real AppLifecycle.seedApp: admission lane + re-check
  node._storageIngressReady = true // start() opens seed ingress after recovery
  const OLD = Date.now() - 10 * 24 * 60 * 60 * 1000
  const wedged = hexKey() // its drive open never settles
  const removed = hexKey() // operator-purged after boot
  const evicted = hexKey() // shed by the same sweep
  const live = hexKey() // a live seed that passed its gate, then queued
  const kept = hexKey()

  let unwedge
  const stuck = new Promise(resolve => { unwedge = resolve })
  const opened = []
  lc._seedAppInner = async (appKey) => {
    if (appKey === wedged) {
      await stuck
      throw new Error('DRIVE_READY_TIMEOUT after 8000ms')
    }
    opened.push(appKey)
    node.appRegistry.apps.set(appKey, { appKey, durability: 0, discoveryKey: 'dk', startedAt: Date.now() })
    return { discoveryKey: 'dk' }
  }

  // load() hydrates a placeholder (no drive yet) for every persisted row.
  for (const k of [wedged, removed, evicted, kept]) {
    node.appRegistry.apps.set(k, { appKey: k, durability: 0, startedAt: OLD })
  }
  const reseeded = []
  lc.on('reseeded', ({ appKey }) => reseeded.push(appKey))
  const replay = lc.reseedDrives([wedged, removed, evicted, kept].map(appKey => ({ appKey })))
  const liveSeed = node.seedApp(live, { maxStorage: BOUND }).then(() => null, (err) => err)
  await new Promise(resolve => setTimeout(resolve, 150))
  t.alike(opened, [], 'everything waits behind the wedged seed')

  // Operator removals while the seeds wait: a boot row, and the app the
  // live seed is queued for (not held: a tombstone-only removal).
  node.appRegistry.delete(removed, { persist: false })
  await node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  await node.manualPurge(live)

  // The sweep sheds `evicted`, then the wedged app; that purge unwedges.
  const surplus = { current: 4, target: 2 }
  const health = new Map([[wedged, surplus], [evicted, surplus]])
  const holders = [myPubkeyHex, hexKey(), hexKey(), hexKey()].map(relayPubkey => ({ relayPubkey }))
  const ev = new EvictionManager({
    appRegistry: node.appRegistry,
    seedingRegistry: { getRelaysForApp: async (k) => (health.has(k) ? holders : []) },
    storageAccounting: { getBytes: (k) => (k === evicted ? 5000 : 0), measure: async () => 0, getSummary: () => ({ totalBytes: 5000 }) },
    diskMonitor: { getInfo: () => ({ usedPct: 95, totalBytes: 20e9 }) },
    getReplicationHealth: () => health,
    myPubkeyHex,
    unseed: async (k) => { node.appRegistry.delete(k, { persist: false }) },
    purgeDrive: async (k) => { if (k === wedged) unwedge() }
  }, { enabled: true, minAgeMs: 0 })
  const res = await ev.sweep()
  t.alike(res.evicted, [evicted, wedged], 'the sweep evicted both')

  await replay
  const liveErr = await liveSeed
  t.alike(opened, [kept], 'only the untouched row re-seeds')
  t.alike(reseeded, [kept], 'the replay re-seeded nothing removed since boot')
  t.is(liveErr && liveErr.code, 'TOMBSTONED', 'the queued live seed is refused once it holds the lane')
  for (const k of [wedged, removed, evicted, live]) {
    t.absent(node.appRegistry.has(k), 'not re-adopted')
    t.ok(node.appRegistry.isEvicted(k), 'tombstone stands')
  }
  t.ok(sent.skipped.some(s => s.appKey === removed && s.source === 'boot-reseed'), 'replay skip logged')
  t.ok(sent.skipped.some(s => s.appKey === live && s.source === 'seed-app'), 'lane re-check logged')
})

test('live: the seed-lane re-check lets a held boot row (sacred, tombstoned) and an operator-lifted seed through', async (t) => {
  const { node } = makeNode(t)
  const lc = node.appLifecycle
  delete lc.seedApp
  node._storageIngressReady = true
  const opened = []
  lc._seedAppInner = async (appKey) => { opened.push(appKey); return { discoveryKey: 'dk' } }
  const archive = hexKey()
  const lifted = hexKey()
  node.appRegistry.apps.set(archive, { appKey: archive, durability: 1 }) // placeholder still held
  await node.appRegistry.markEvicted(archive, 1000, { kind: TOMBSTONE_OPERATOR })
  await node.appRegistry.markEvicted(lifted, 1000, { kind: TOMBSTONE_OPERATOR })
  await node.clearTombstone(lifted) // POST /seed, approveRequest, CLI --seed

  await lc.reseedDrives([{ appKey: archive }])
  await node.seedApp(lifted, { maxStorage: BOUND })
  t.alike(opened, [archive, lifted], 'both seeded')
})
