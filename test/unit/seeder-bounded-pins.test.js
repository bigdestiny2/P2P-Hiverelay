/**
 * Seeder bounded bare-core pins (v0.24.5).
 *
 * Production bug (2026-10-26): PearTube seed requests listed per-video blob
 * cores in `discoveryKeys`; Seeder.seedCore downloaded each in full with no
 * bound or capacity check, counted bytes only via in-process 'download'
 * events (so ~0 after a restart), and unseedCore never deleted files. Relays
 * reported 0–24 GB stored while 40+ GB of pinned video sat on disk; disks
 * hit 100% (ENOSPC crash loops).
 *
 * The purge / restart-accounting tests use real corestore<->corestore
 * replication (hypercore 10.38) so they exercise the actual info({ storage })
 * and purge() behaviour the fix relies on; the policy tests (budgets,
 * reservations, admission) use event-emitting fake cores for determinism.
 */

import test from 'brittle'
import b4a from 'b4a'
import Corestore from 'corestore'
import { EventEmitter } from 'events'
import { mkdtempSync, rmSync } from 'fs'
import { readFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'
import { dirBytes } from 'p2p-hiverelay/core/relay-node/storage-accounting.js'

const BLOCK = 64 * 1024
const BLOCKS = 32 // 2 MiB "video"
const VIDEO_BYTES = BLOCK * BLOCKS

const swarm = { join () {}, async leave () {} }

function tmpDir (t, prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.teardown(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function waitForEvent (emitter, name, ms = 15_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for ' + name)), ms)
    emitter.once(name, (e) => { clearTimeout(timer); resolve(e) })
  })
}

async function waitFor (fn, ms = 15_000) {
  const started = Date.now()
  while (!(await fn())) {
    if (Date.now() - started > ms) throw new Error('timed out waiting for condition')
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
}

// A publisher with one multi-block core (a stand-in for a video blob core),
// replicated into a fresh relay store.
async function setup (t) {
  const pubDir = tmpDir(t, 'pins-pub-')
  const relayDir = tmpDir(t, 'pins-relay-')
  const pub = new Corestore(pubDir)
  const video = pub.get({ name: 'video' })
  await video.ready()
  const block = b4a.alloc(BLOCK, 7)
  const batch = []
  for (let i = 0; i < BLOCKS; i++) batch.push(block)
  await video.append(batch)

  const relay = new Corestore(relayDir)
  await relay.ready()
  const s1 = pub.replicate(true)
  const s2 = relay.replicate(false)
  s1.pipe(s2).pipe(s1)
  const unlink = () => { s1.destroy(); s2.destroy() }

  return { pub, relay, video, relayDir, keyHex: b4a.toString(video.key, 'hex'), unlink }
}

async function teardownStores (...stores) {
  for (const s of stores) { try { await s.close() } catch (_) {} }
}

async function readPersisted (path) {
  try { return JSON.parse(await readFile(path, 'utf8')) } catch { return null }
}

// ─── real hypercore: purge + restart accounting ────────────────────

test('bound overflow: a core bigger than its bound is dropped AND purged', async (t) => {
  const { pub, relay, relayDir, keyHex, unlink } = await setup(t)
  const storagePath = join(relayDir, 'seeded-cores.json')
  const seeder = new Seeder(relay, swarm, { storagePath, maxStorageBytes: 1024 ** 3 })
  await seeder.start()

  const exceeded = waitForEvent(seeder, 'core-bound-exceeded')
  // The upgrade may land before seedCore returns (then it rejects with
  // BOUND_EXCEEDED) or after (then the 'append' check drops it) — both paths
  // must end in the same place.
  const pinned = seeder.seedCore(keyHex, { maxStorageBytes: VIDEO_BYTES / 4, group: 'a'.repeat(64), source: 'seed-request' })
  pinned.catch(() => {})
  const ev = await exceeded

  t.is(ev.publicKeyHex, keyHex)
  t.is(ev.reason, 'core-bound')
  t.is(ev.byteLength, VIDEO_BYTES, 'learned the real size from the upgrade')
  t.is(ev.maxStorageBytes, VIDEO_BYTES / 4)
  t.is(ev.purged, true, 'storage purged, not just closed')
  t.absent(seeder.cores.has(keyHex), 'pin removed')
  t.is(seeder.totalBytesStored, 0, 'its bytes left the accounting')
  t.is(seeder.pendingBytes(), 0, 'its reservation was released')
  t.ok(await dirBytes(join(relayDir, 'cores')) < VIDEO_BYTES / 4, 'core files are gone from disk')

  await seeder._persistTail
  const persisted = await readPersisted(storagePath)
  t.absent((persisted?.cores || []).includes(keyHex), 'not re-seeded after a restart')

  // A publisher re-sending the same request must not make us re-download it.
  await t.exception(seeder.seedCore(keyHex, { maxStorageBytes: VIDEO_BYTES / 4 }), /does not fit/, 'oversize memo refuses the re-request')
  await t.execution(seeder.seedCore(keyHex, { maxStorageBytes: VIDEO_BYTES * 2 }), 'a request whose budget fits is accepted again')

  await seeder.stop()
  unlink()
  await teardownStores(relay, pub)
})

test('unseedCore purges storage so the bytes actually return', async (t) => {
  const { pub, relay, relayDir, keyHex, unlink } = await setup(t)
  const seeder = new Seeder(relay, swarm, {})
  await seeder.start()

  const entry = await seeder.seedCore(keyHex, { maxStorageBytes: VIDEO_BYTES * 2 })
  await waitFor(() => entry.core.length === BLOCKS && entry.core.contiguousLength === BLOCKS)
  const before = await dirBytes(join(relayDir, 'cores'))
  t.ok(before >= VIDEO_BYTES, 'video is on disk (' + before + ' bytes)')
  t.ok(seeder.totalBytesStored >= VIDEO_BYTES, 'and counted')

  const res = await seeder.unseedCore(keyHex)
  t.is(res.purged, true, 'purged')
  t.ok(res.freedBytes >= VIDEO_BYTES, 'reports the bytes it freed (' + res.freedBytes + ')')
  const after = await dirBytes(join(relayDir, 'cores'))
  t.ok(before - after >= VIDEO_BYTES, 'disk usage dropped by at least the video size (' + before + ' -> ' + after + ')')
  t.is(seeder.totalBytesStored, 0)

  await seeder.stop()
  unlink()
  await teardownStores(relay, pub)
})

test('restart accounting: pinned bytes are derived from storage on ready()', async (t) => {
  const { pub, relay, relayDir, keyHex, unlink } = await setup(t)
  const storagePath = join(relayDir, 'seeded-cores.json')
  const group = 'b'.repeat(64)

  const s1 = new Seeder(relay, swarm, { storagePath })
  await s1.start()
  const entry = await s1.seedCore(keyHex, { maxStorageBytes: VIDEO_BYTES * 4, group, source: 'seed-request' })
  await waitFor(() => entry.core.contiguousLength === BLOCKS)
  await s1._persistTail
  await s1.stop()
  unlink()
  await relay.close()

  // Fresh process: no 'download' events will ever fire for these blocks.
  const relay2 = new Corestore(relayDir)
  await relay2.ready()
  const s2 = new Seeder(relay2, swarm, { storagePath })
  await s2.start()

  const restored = s2.cores.get(keyHex)
  t.ok(restored, 'pin restored')
  t.ok(s2.totalBytesStored >= VIDEO_BYTES, 'stored bytes survive the restart (' + s2.totalBytesStored + ', was ~0 before v0.24.5)')
  t.is(restored.bytesStored, s2.totalBytesStored)
  t.is(restored.knownByteLength, VIDEO_BYTES, 'size known from local storage')
  t.is(restored.maxStorageBytes, VIDEO_BYTES * 4, 'bound survived the restart')
  t.is(restored.group, group)
  t.is(restored.source, 'seed-request')
  t.is(s2.pendingBytes(), 0, 'nothing outstanding for a complete pin')

  await s2.stop()
  await teardownStores(relay2, pub)
})

test('evictCore purges; writable cores are never purged (our own data)', async (t) => {
  const { pub, relay, relayDir, keyHex, video, unlink } = await setup(t)

  // Remote pin: evictable, purge frees its bytes.
  const seeder = new Seeder(relay, swarm, {})
  await seeder.start()
  const entry = await seeder.seedCore(keyHex)
  await waitFor(() => entry.core.contiguousLength === BLOCKS)
  const res = await seeder.evictCore(keyHex)
  t.is(res.evicted, true)
  t.is(res.purged, true)
  t.ok(res.freedBytes >= VIDEO_BYTES)
  t.ok(await dirBytes(join(relayDir, 'cores')) < VIDEO_BYTES / 4)

  // The publisher's own (writable) core, pinned on its own store — e.g. the
  // outboxlog journal. Never evicted, and unseed keeps the files.
  const own = new Seeder(pub, swarm, {})
  await own.start()
  const ownEntry = await own.seedCore(b4a.toString(video.key, 'hex'))
  t.is(ownEntry.writable, true)
  t.alike(await own.evictCore(keyHex), { evicted: false, skipped: 'writable', freedBytes: 0, purged: false })
  const skipped = waitForEvent(own, 'purge-skipped')
  const unseeded = await own.unseedCore(keyHex)
  t.is(unseeded.purged, false, 'writable core released, not purged')
  t.is((await skipped).reason, 'writable')
  t.is(video.length, BLOCKS, 'publisher data intact')

  await own.stop()
  await seeder.stop()
  unlink()
  await teardownStores(relay, pub)
})

// ─── policy (fake cores) ───────────────────────────────────────────

// Event-emitting fake core: tests drive length/byteLength and 'append'.
function fakeCore (keyHex, opts = {}) {
  const core = new EventEmitter()
  core.key = b4a.from(keyHex, 'hex')
  core.discoveryKey = b4a.alloc(32, 1)
  core.length = opts.length || 0
  core.byteLength = opts.byteLength || 0
  core.writable = opts.writable === true
  core.closed = false
  core.purged = false
  core.ready = async () => { if (opts.readyError) throw opts.readyError }
  core.info = async () => ({ length: core.length, byteLength: core.byteLength, contiguousLength: 0, storage: { oplog: 0, tree: 0, blocks: opts.stored || 0, bitfield: 0 } })
  core.download = () => ({ done: () => new Promise(() => {}), destroy () {} })
  core.close = async () => { core.closed = true }
  core.purge = async () => { core.purged = true; core.closed = true }
  core.grow = (byteLength) => { core.length = Math.max(1, core.length + 1); core.byteLength = byteLength; core.emit('append') }
  return core
}

function fakeStore (overrides = {}) {
  const cores = new Map()
  const gets = []
  return {
    gets,
    cores,
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      gets.push(hex)
      const core = fakeCore(hex, overrides[hex] || {})
      cores.set(hex, core)
      return core
    }
  }
}

const K1 = '11'.repeat(32)
const K2 = '22'.repeat(32)
const K3 = '33'.repeat(32)
const APP = 'aa'.repeat(32)

test('admission: a budgeted pin is refused when the relay cannot fit it', async (t) => {
  const store = fakeStore()
  let available = 1000
  const seeder = new Seeder(store, swarm, { getAvailableBytes: () => available })
  await seeder.start()

  await t.exception(seeder.seedCore(K1, { maxStorageBytes: 2000 }), /INSUFFICIENT|bytes available/)
  try { await seeder.seedCore(K1, { maxStorageBytes: 2000 }) } catch (err) { t.is(err.code, 'INSUFFICIENT_STORAGE') }
  t.is(store.gets.length, 0, 'refused before opening the core')

  available = 5000
  await seeder.seedCore(K1, { maxStorageBytes: 2000 })
  t.is(seeder.pendingBytes(), 2000, 'budget reserved until the size is known')
  store.cores.get(K1).grow(700)
  t.is(seeder.pendingBytes(), 700, 'reservation shrinks to the known size')
  await seeder.stop()
})

test('admission: the request budget is shared by its cores and reserved once', async (t) => {
  const store = fakeStore()
  const seeder = new Seeder(store, swarm, { getAvailableBytes: () => 10_000 })
  await seeder.start()

  // Both calls start synchronously (as RelayNode does) before either opens.
  const p1 = seeder.seedCore(K1, { maxStorageBytes: 1500, group: APP, source: 'seed-request' })
  const p2 = seeder.seedCore(K2, { maxStorageBytes: 1500, group: APP, source: 'seed-request' })
  t.is(seeder.pendingBytes(), 1500, 'one group reservation, not one per core')
  await Promise.all([p1, p2])

  const dropped = []
  seeder.on('core-bound-exceeded', (e) => dropped.push(e))
  store.cores.get(K1).grow(1000) // fits alone
  store.cores.get(K2).grow(800) //  1000 + 800 > 1500 → K2 pushed it over
  await waitFor(() => dropped.length === 1)

  t.is(dropped[0].publicKeyHex, K2, 'the core that crossed the budget is dropped')
  t.is(dropped[0].reason, 'group-budget')
  t.is(dropped[0].groupBytes, 1800)
  t.is(dropped[0].purged, true)
  t.ok(seeder.cores.has(K1), 'the rest of the group is kept')
  t.ok(store.cores.get(K2).purged, 'dropped core purged')
  await seeder.stop()
})

test('admission: the group budget counts the app drive (groupBaseBytes)', async (t) => {
  const store = fakeStore()
  const seeder = new Seeder(store, swarm, { getAvailableBytes: () => 10_000, groupBaseBytes: (g) => (g === APP ? 600 : 0) })
  await seeder.start()
  await seeder.seedCore(K1, { maxStorageBytes: 1500, group: APP, source: 'seed-request' })
  const dropped = waitForEvent(seeder, 'core-bound-exceeded')
  store.cores.get(K1).grow(1000) // 600 (app) + 1000 > 1500
  const ev = await dropped
  t.is(ev.reason, 'group-budget')
  t.is(ev.groupBytes, 1600)
  await seeder.stop()
})

test('admission: a later request raises the group budget (delta reserved), never lowers it', async (t) => {
  const store = fakeStore()
  let available = 10_000
  const seeder = new Seeder(store, swarm, { getAvailableBytes: () => available - seeder.pendingBytes() })
  await seeder.start()
  await seeder.seedCore(K1, { maxStorageBytes: 1000, group: APP, source: 'seed-request' })

  // A re-request with a smaller budget (e.g. an SDK default) adopts the
  // existing one — it must not shrink the group and purge held pins.
  const e2 = await seeder.seedCore(K2, { maxStorageBytes: 100, group: APP, source: 'seed-request' })
  t.is(e2.maxStorageBytes, 1000)

  // A larger one raises it for every member; only the delta must fit.
  available = 1000 + 600 // 1000 already reserved by the group
  await t.exception(seeder.seedCore(K3, { maxStorageBytes: 2000, group: APP, source: 'seed-request' }), /bytes available/, 'delta 1000 does not fit in 600')
  available = 1000 + 1200
  const e3 = await seeder.seedCore(K3, { maxStorageBytes: 2000, group: APP, source: 'seed-request' })
  t.is(e3.maxStorageBytes, 2000)
  t.is(seeder.cores.get(K1).maxStorageBytes, 2000, 'raised for the whole group')
  t.is(seeder.pendingBytes(), 2000, 'still one reservation for the group')
  await seeder.stop()
})

test('default pins (no opts) keep working: bound = relay cap, refused only when full', async (t) => {
  const store = fakeStore({ [K2]: { writable: true } })
  let available = 1
  const seeder = new Seeder(store, swarm, { maxStorageBytes: 5000, getAvailableBytes: () => available })
  await seeder.start()

  const entry = await seeder.seedCore(K1)
  t.is(entry.source, 'local')
  t.is(entry.maxStorageBytes, null, 'default bound (relay cap, read live)')
  t.is(seeder.pendingBytes(), 0, 'no up-front reservation')

  available = 0
  await t.exception(seeder.seedCore(K3), /storage is full/, 'refused once the relay is full')
  t.ok(store.cores.get(K3).closed, 'refused core closed')
  await t.execution(seeder.seedCore(K2), 'our own writable core (outboxlog journal) is pinned even when full')

  // A default pin that outgrows the whole relay cap is dropped.
  const dropped = waitForEvent(seeder, 'core-bound-exceeded')
  store.cores.get(K1).grow(6000)
  t.is((await dropped).maxStorageBytes, 5000)
  await seeder.stop()
})

test('upload events stamp lastServedAt; listPins exposes eviction inputs', async (t) => {
  const store = fakeStore({ [K1]: { stored: 4096 } })
  const seeder = new Seeder(store, swarm, {})
  await seeder.start()
  await seeder.seedCore(K1, { maxStorageBytes: 10_000, group: APP, source: 'seed-request' })
  const [pin] = seeder.listPins()
  t.is(pin.lastServedAt, 0, 'never served yet')
  t.is(pin.bytesStored, 4096, 'measured from storage on ready()')
  t.is(pin.source, 'seed-request')

  const before = Date.now()
  store.cores.get(K1).emit('upload', 0, 512)
  t.ok(seeder.listPins()[0].lastServedAt >= before)
  t.is(seeder.totalBytesServed, 512)
  await seeder.stop()
})
