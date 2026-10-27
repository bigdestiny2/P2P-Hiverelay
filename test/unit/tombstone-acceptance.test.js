/**
 * Sticky operator tombstones + tombstone-aware acceptance (v0.24.7).
 *
 * Production bug (2026-10-27): an operator removed ~400 apps fleet-wide
 * (manual purge: unseed + purge + tombstone), then flipped the fleet back
 * to open accept mode. Within minutes 97 of them were seeded again: the
 * persistent seed-request log replay and live seed requests never checked
 * the tombstone, and the one gate that did (replication repair) clears it
 * whenever the network is under the replica floor — which a fleet-wide
 * removal always is.
 *
 * Now every acceptance path refuses a tombstoned app, and tombstones carry
 * a kind: operator removals are sticky (only an explicit operator seed
 * lifts them), eviction tombstones keep the under-floor re-adoption.
 *
 * Same in-process pattern as seed-admission.test.js: a constructed (not
 * started) RelayNode with the network-facing pieces stubbed. The real
 * RelayNode.seedApp runs (so its tombstone backstop is exercised); only
 * appLifecycle.seedApp — the drive/swarm work — is stubbed.
 */

import test from 'brittle'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { mkdtemp, readFile, writeFile } from 'fs/promises'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { AppRegistry, TOMBSTONE_EVICTION, TOMBSTONE_OPERATOR } from 'p2p-hiverelay/core/app-registry.js'
import { runOperatorSeedAction } from 'p2p-hiverelay/core/relay-node/api-seed-publish.js'

const GiB = 1024 * 1024 * 1024

function tmpStorage () {
  return path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex'))
}

function hexKey () {
  return randomBytes(32).toString('hex')
}

function makeNode (t, { acceptMode = 'open' } = {}) {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const realStore = node.store
  t.teardown(async () => {
    try { await realStore.close() } catch (_) {}
  })
  node.config.acceptMode = acceptMode
  node.config.maxStorageBytes = 10 * GiB
  node.config.targetReplicaFloor = 2
  const myPubkey = randomBytes(32)
  node.swarm = { keyPair: { publicKey: myPubkey } }

  const sent = { seeded: [], accepts: [], denies: [], acceptances: [], skipped: [], cleared: [] }
  node.appLifecycle.seedApp = async (key) => {
    sent.seeded.push(key)
    node.appRegistry.apps.set(key, { appKey: key, durability: 0 })
    return { appKey: key }
  }
  node.seeder = {
    cores: new Map(),
    totalBytesStored: 0,
    seedCore: async () => {}
  }
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
    maxStorageBytes: 0,
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
    maxStorageBytes: 0,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0
  }
}

// ─── AppRegistry: kinds + sidecar compatibility ─────────────────────

test('tombstones: a legacy evicted.json ({appKey: timestampMs}) loads as eviction tombstones', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-legacy-'))
  const a = 'aa'.repeat(32)
  const b = 'bb'.repeat(32)
  await writeFile(path.join(dir, 'evicted.json'), JSON.stringify({ [a]: 1000, [b]: 2000, junk: 'x' }))

  const reg = new AppRegistry(dir)
  await reg.load()
  t.ok(reg.isEvicted(a) && reg.isEvicted(b), 'legacy tombstones loaded')
  t.alike(reg.getTombstone(a), { at: 1000, kind: TOMBSTONE_EVICTION }, 'legacy entry is an eviction tombstone')
  t.absent(reg.isEvicted('junk'), 'non-numeric legacy value ignored')
  t.ok(reg.clearEvicted(b), 'legacy (eviction) tombstone still clears under the floor rule')
})

test('tombstones: operator kind round-trips; eviction entries keep the legacy number format', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'tomb-kinds-'))
  const op = 'cc'.repeat(32)
  const ev = 'dd'.repeat(32)
  const reg1 = new AppRegistry(dir)
  reg1.markEvicted(op, 5000, { kind: TOMBSTONE_OPERATOR })
  reg1.markEvicted(ev, 6000)
  await reg1._evictedPersistTail

  const raw = JSON.parse(await readFile(path.join(dir, 'evicted.json'), 'utf8'))
  t.is(raw[ev], 6000, 'eviction tombstone written as a bare timestamp (downgrade-safe)')
  t.alike(raw[op], { at: 5000, kind: TOMBSTONE_OPERATOR }, 'operator tombstone written with its kind')

  const reg2 = new AppRegistry(dir)
  await reg2.load()
  t.alike(reg2.getTombstone(op), { at: 5000, kind: TOMBSTONE_OPERATOR }, 'operator kind survives reload')
  t.alike(reg2.getTombstone(ev), { at: 6000, kind: TOMBSTONE_EVICTION }, 'eviction kind survives reload')
})

test('tombstones: an operator tombstone only clears with an explicit operator action', (t) => {
  const reg = new AppRegistry(null)
  const k = 'ee'.repeat(32)
  reg.markEvicted(k, 1, { kind: TOMBSTONE_OPERATOR })
  t.is(reg.clearEvicted(k), false, 'plain clear (the under-floor rule) refused')
  t.ok(reg.isEvicted(k), 'still tombstoned')
  reg.markEvicted(k, 2) // a later automatic shed must not downgrade it
  t.is(reg.getTombstone(k).kind, TOMBSTONE_OPERATOR, 'never downgraded to eviction')
  t.is(reg.clearEvicted(k, { operator: true }), true, 'operator clear lifts it')
  t.absent(reg.isEvicted(k), 'gone')
})

test('tombstones: the size bound sheds old eviction tombstones, never operator ones', (t) => {
  const reg = new AppRegistry(null)
  const op = 'ff'.repeat(32)
  reg.markEvicted(op, 0, { kind: TOMBSTONE_OPERATOR }) // the oldest entry
  for (let i = 1; i <= 5000; i++) reg.markEvicted(i.toString(16).padStart(64, '0'), i)
  t.is(reg.evicted.size, 5000, 'bounded')
  t.ok(reg.isEvicted(op), 'oldest entry is an operator removal and survives the bound')
  t.absent(reg.isEvicted((1).toString(16).padStart(64, '0')), 'oldest eviction tombstone fell off instead')
})

// ─── Boot replay of the persistent seed-request log ─────────────────

test('open mode: registry-log replay skips tombstoned apps (re-seed-after-restart and fresh-accept branches)', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  const replayed = hexKey() // this relay accepted it before the removal
  const fresh = hexKey() // never accepted here
  const evicted = hexKey()
  const control = hexKey()
  node.appRegistry.markEvicted(replayed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  node.appRegistry.markEvicted(fresh, Date.now(), { kind: TOMBSTONE_OPERATOR })
  node.appRegistry.markEvicted(evicted, Date.now())
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
  t.is(sent.skipped.find(s => s.appKey === replayed).kind, TOMBSTONE_OPERATOR, 'skip carries the tombstone kind')

  await node._scanRegistry()
  t.is(sent.skipped.length, 3, 'repeat scans do not re-log the same skip (rate-limited)')
})

test('review mode: registry-log replay does not re-queue a tombstoned app', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t, { acceptMode: 'review' })
  const removed = hexKey()
  node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })
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
  node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })
  node.appRegistry.markEvicted(evicted, Date.now())

  node._onSeedRequest(seedRequest(removed), {})
  node._onSeedRequest(seedRequest(evicted), {})
  await new Promise(resolve => setImmediate(resolve))

  t.is(sent.accepts.length, 0, 'no accept sent')
  t.is(sent.seeded.length, 0, 'nothing seeded')
  t.alike(sent.denies.map(d => d.reasonCode), ['tombstoned:operator', 'tombstoned:eviction'], 'denied with the tombstone reason')
  t.alike(sent.skipped.map(s => s.source), ['seed-request', 'seed-request'], 'skips logged')

  // Control: the same open relay accepts an untombstoned request.
  const control = hexKey()
  node._onSeedRequest(seedRequest(control), {})
  await new Promise(resolve => setImmediate(resolve))
  t.alike(sent.accepts, [control], 'open mode still accepts everything else')
  t.alike(sent.seeded, [control], 'and seeds it')
})

test('seedApp backstop: a tombstoned app is refused; an explicit operator seed lifts the tombstone', async (t) => {
  const { node, sent } = makeNode(t)
  const removed = hexKey()
  node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  await t.exception(() => node.seedApp(removed), /TOMBSTONED/, 'automatic callers get TOMBSTONED')
  t.is(sent.seeded.length, 0, 'nothing seeded')

  const out = await runOperatorSeedAction({ body: { appKey: removed }, node })
  t.ok(out.ok, 'operator POST /seed succeeds')
  t.alike(sent.seeded, [removed], 'operator seed re-adopts the app')
  t.absent(node.appRegistry.isEvicted(removed), 'tombstone lifted')
  t.alike(sent.cleared, [{ appKey: removed, kind: TOMBSTONE_OPERATOR }], 'lift is logged')
})

// ─── Replication repair: operator vs eviction tombstones ────────────

function repairRequest (appKey) {
  return { appKey, publisherPubkey: hexKey(), privacyTier: 'public', contentType: 'app' }
}

const UNDER_FLOOR = { current: 0, target: 3, relays: [] }

test('repair: an operator tombstone survives under-floor repair', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const removed = hexKey()
  node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  const repaired = await node._attemptReplicationRepair(repairRequest(removed), UNDER_FLOOR)

  t.is(repaired, false, 'not repaired')
  t.is(sent.seeded.length, 0, 'not seeded')
  t.alike(node.appRegistry.getTombstone(removed).kind, TOMBSTONE_OPERATOR, 'operator tombstone intact')
  t.is(sent.skipped[0] && sent.skipped[0].source, 'replication-repair', 'skip logged')
})

test('repair: manualPurge leaves an operator tombstone that under-floor repair cannot clear', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const app = hexKey()
  node.appRegistry.apps.set(app, { appKey: app, durability: 0 })
  node.unseedApp = async (k) => { node.appRegistry.apps.delete(k) }
  node.store = {
    session () { throw new Error('no drive session in this test') },
    get () { return { ready: async () => {}, purge: async () => {}, close: async () => {} } }
  }

  const out = await node.manualPurge(app)
  t.is(out.method, 'meta-only', 'purged')
  t.is(node.appRegistry.getTombstone(app).kind, TOMBSTONE_OPERATOR, 'manual purge writes an operator tombstone')

  t.is(await node._attemptReplicationRepair(repairRequest(app), UNDER_FLOOR), false, 'repair refuses')
  t.ok(node.appRegistry.isEvicted(app), 'tombstone survives')
  t.is(sent.seeded.length, 0, 'never re-seeded')
})

test('manualPurge: an unheld key (e.g. a pre-0.24.7 eviction tombstone) becomes a sticky operator tombstone', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const legacy = hexKey()
  node.appRegistry.markEvicted(legacy, 1000) // what a v0.24.6 removal left behind

  const out = await node.manualPurge(legacy)
  t.alike(out, { appKey: legacy, bytes: 0, method: 'tombstone-only' }, 'nothing to purge, tombstone recorded')
  t.is(node.appRegistry.getTombstone(legacy).kind, TOMBSTONE_OPERATOR, 'upgraded to an operator tombstone')

  t.is(await node._attemptReplicationRepair(repairRequest(legacy), UNDER_FLOOR), false, 'under-floor repair now refuses')
  t.ok(node.appRegistry.isEvicted(legacy), 'tombstone survives')
  t.is(sent.seeded.length, 0, 'never re-seeded')
})

test('repair: review mode does not re-queue an operator-removed app', async (t) => {
  const { node, myPubkeyHex } = makeNode(t, { acceptMode: 'review' })
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const removed = hexKey()
  node.appRegistry.markEvicted(removed, Date.now(), { kind: TOMBSTONE_OPERATOR })

  await node._attemptReplicationRepair(repairRequest(removed), UNDER_FLOOR)
  t.is(node._pendingRequests.size, 0, 'not queued')
})

test('repair: an eviction tombstone is still re-adopted under the floor', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const shed = hexKey()
  node.appRegistry.markEvicted(shed, Date.now())

  const repaired = await node._attemptReplicationRepair(repairRequest(shed), UNDER_FLOOR)

  t.is(repaired, true, 'repaired')
  t.alike(sent.seeded, [shed], 're-seeded')
  t.absent(node.appRegistry.isEvicted(shed), 'eviction tombstone cleared (we are needed again)')
  t.alike(node.seedingRegistry.acceptances, [shed], 'acceptance recorded')
})

test('repair: an eviction tombstone at or above the floor is kept', async (t) => {
  const { node, sent, myPubkeyHex } = makeNode(t)
  node.seedingRegistry = fakeSeedingRegistry([], { myPubkeyHex })
  const shed = hexKey()
  node.appRegistry.markEvicted(shed, Date.now())

  const atFloor = { current: 2, target: 3, relays: [{ relayPubkey: hexKey() }, { relayPubkey: hexKey() }] }
  t.is(await node._attemptReplicationRepair(repairRequest(shed), atFloor), false, 'not repaired')
  t.is(sent.seeded.length, 0, 'not seeded')
  t.ok(node.appRegistry.isEvicted(shed), 'tombstone kept')
})

// ─── Boot replay of the local registry ──────────────────────────────

function bootStore (purged) {
  return {
    session () { throw new Error('no drive session in this test') },
    get (key) {
      return {
        ready: async () => {},
        purge: async () => { purged.push(b4a.toString(key, 'hex')) },
        close: async () => {}
      }
    }
  }
}

test('boot: a held row that also carries a tombstone is dropped and purged, not re-seeded (any accept mode)', async (t) => {
  const { node, sent } = makeNode(t, { acceptMode: 'review' })
  const purged = []
  node.store = bootStore(purged)
  const readopted = hexKey() // removed, then re-adopted by a ≤0.24.6 path
  const kept = hexKey()
  for (const k of [readopted, kept]) node.appRegistry.apps.set(k, { appKey: k, durability: 0 })
  node.appRegistry.markEvicted(readopted, 1000) // legacy row from the v0.24.6 removal

  const entries = await node._dropTombstonedEntries([{ appKey: readopted }, { appKey: kept }])
  await new Promise(resolve => setImmediate(resolve))

  t.alike(entries.map(e => e.appKey), [kept], 'only the untombstoned row is replayed')
  t.absent(node.appRegistry.has(readopted), 'tombstoned row forgotten')
  t.ok(node.appRegistry.has(kept), 'other rows untouched')
  t.ok(node.appRegistry.isEvicted(readopted), 'tombstone still stands')
  t.alike(purged, [readopted], 'its cores are purged')
  t.alike(sent.skipped.map(s => [s.appKey, s.source]), [[readopted, 'boot-reseed']], 'skip logged')

  // Now unheld, the registry scan's gates apply: no pending, no seed.
  node.seedingRegistry = fakeSeedingRegistry([registryRequest(readopted)], { myPubkeyHex: hexKey() })
  await node._scanRegistry()
  t.is(node._pendingRequests.size, 0, 'not queued for approval')
  t.is(sent.seeded.length, 0, 'not seeded')
})

test('boot: sacred rows keep seeding even with a stale tombstone', async (t) => {
  const { node } = makeNode(t)
  const purged = []
  node.store = bootStore(purged)
  const archive = hexKey()
  const custody = hexKey()
  node.appRegistry.apps.set(archive, { appKey: archive, durability: 1 })
  node.appRegistry.apps.set(custody, { appKey: custody, durability: 0, custodyIntentId: 'intent-1' })
  node.appRegistry.markEvicted(archive, 1000)
  node.appRegistry.markEvicted(custody, 1000, { kind: TOMBSTONE_OPERATOR })

  const entries = await node._dropTombstonedEntries([{ appKey: archive }, { appKey: custody }])
  t.is(entries.length, 2, 'both replayed')
  t.ok(node.appRegistry.has(archive) && node.appRegistry.has(custody), 'rows kept')
  t.is(purged.length, 0, 'nothing purged')
})
