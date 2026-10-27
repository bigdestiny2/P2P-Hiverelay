/**
 * Seeder bare-core persistence (v0.18.x).
 *
 * /seed-core pins (catalog bees + any plain Hypercore) must survive a relay
 * restart. These pin the contract: seedCore persists, unseedCore removes,
 * stop() (teardown) does NOT wipe the list, and a fresh Seeder.start()
 * re-seeds exactly what was pinned. The last two are the load-bearing ones —
 * a persisting unseed in stop() would empty the file on every clean shutdown.
 */

import test from 'brittle'
import b4a from 'b4a'
import { mkdtemp, readFile, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'

const K1 = 'a'.repeat(64)
const K2 = 'b'.repeat(64)

function fakeCore (keyHex) {
  const key = b4a.from(keyHex, 'hex')
  const discoveryKey = b4a.alloc(32)
  discoveryKey[0] = key[0] // distinct per key; content irrelevant to the fakes
  return {
    key,
    discoveryKey,
    length: 0,
    async ready () {},
    download () { return { async done () {}, destroy () {} } },
    on () {},
    async close () {}
  }
}

function fakeDeps () {
  const requested = []
  const store = {
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      requested.push(hex)
      return fakeCore(hex)
    }
  }
  const swarm = { join () {}, async leave () {} }
  return { store, swarm, requested }
}

async function readCores (path) {
  try { return JSON.parse(await readFile(path, 'utf8')).cores } catch { return null }
}

test('seedCore persists; unseedCore removes', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()

  await s.seedCore(K1)
  await s.seedCore(K2)
  await s._persistTail // drain the serialized writer
  t.alike((await readCores(path)).sort(), [K1, K2].sort(), 'both keys persisted')

  await s.unseedCore(K1)
  await s._persistTail
  t.alike(await readCores(path), [K2], 'unseed removed K1 from the persisted set')

  await s.stop()
})

test('stop() does NOT wipe the persisted list (restart-safety guard)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()
  await s.seedCore(K1)
  await s.seedCore(K2)
  await s._persistTail

  await s.stop() // teardown — must release resources but keep the list
  t.is(s.cores.size, 0, 'in-memory cores cleared on stop')
  t.alike((await readCores(path)).sort(), [K1, K2].sort(), 'persisted list survives a clean shutdown')
})

test('start() re-seeds the persisted cores', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')

  // First run: pin two, then shut down.
  const a = fakeDeps()
  const s1 = new Seeder(a.store, a.swarm, { storagePath: path })
  await s1.start()
  await s1.seedCore(K1)
  await s1.seedCore(K2)
  await s1._persistTail
  await s1.stop()

  // Restart: a fresh Seeder over the same storagePath must re-seed both.
  const b = fakeDeps()
  const s2 = new Seeder(b.store, b.swarm, { storagePath: path })
  await s2.start()
  t.alike(b.requested.sort(), [K1, K2].sort(), 'store.get called for each persisted key on start')
  t.is(s2.cores.size, 2, 'both cores re-seeded into memory')
  // Re-seeding did not corrupt the persisted set.
  await s2._persistTail
  t.alike((await readCores(path)).sort(), [K1, K2].sort())
  await s2.stop()
})

test('start() tolerates a missing/corrupt persist file', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path }) // file doesn't exist
  await s.start() // must not throw
  t.is(s.cores.size, 0)
  await s.stop()
})

test('no storagePath -> persistence is a no-op (no throw)', async (t) => {
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, {}) // null storagePath
  await s.start()
  await s.seedCore(K1)
  t.is(s.cores.size, 1)
  await s.stop()
})

// ─── v0.24.5: bounds + LRU metadata, backward-compatible format ────

const K3 = 'c'.repeat(64)
const GROUP = 'd'.repeat(64)

async function readFileJson (path) {
  try { return JSON.parse(await readFile(path, 'utf8')) } catch { return null }
}

test('old-format file (bare hex strings) restores as legacy pins', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({ schemaVersion: 1, cores: [K1, K2] }))

  const { store, swarm, requested } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()
  t.alike(requested.sort(), [K1, K2].sort(), 'every v0.24.4 pin re-seeded')
  const e1 = s.cores.get(K1)
  t.is(e1.source, 'legacy', 'origin unknown -> legacy')
  t.is(e1.maxStorageBytes, null, 'default bound (relay cap)')
  t.is(e1.pinnedAt, 0, 'pin time unknown -> treated as old by the sweep')
  t.is(e1.lastServedAt, 0)
  await s.stop()
})

test('new pins persist bounds + LRU metadata; `cores` keeps the old string shape for rollback', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({ schemaVersion: 1, cores: [K1] }))

  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()
  await s.seedCore(K3, { maxStorageBytes: 4096, group: GROUP, source: 'seed-request' })
  await s._persistTail

  const data = await readFileJson(path)
  t.is(data.schemaVersion, 1, 'schema version unchanged — a v0.24.4 binary still reads it')
  t.alike(data.cores.sort(), [K1, K3].sort(), 'cores is still an array of hex strings')
  const pin = data.pins.find(p => p.key === K3)
  t.is(pin.maxStorageBytes, 4096)
  t.is(pin.group, GROUP)
  t.is(pin.source, 'seed-request')
  t.ok(pin.pinnedAt > 0)
  t.is(pin.lastServedAt, 0)
  t.is(data.pins.find(p => p.key === K1).source, 'legacy', 'legacy entry rewritten as an object, still legacy')
  await s.stop()

  // Restart: the bound and metadata come back.
  const b = fakeDeps()
  const s2 = new Seeder(b.store, b.swarm, { storagePath: path })
  await s2.start()
  const e3 = s2.cores.get(K3)
  t.is(e3.maxStorageBytes, 4096, 'bound survives restart')
  t.is(e3.group, GROUP)
  t.is(e3.source, 'seed-request')
  t.is(e3.pinnedAt, pin.pinnedAt, 'pin time survives restart (minAgeMs)')
  await s2.stop()
})

test('object entries inside `cores` are accepted too', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({
    schemaVersion: 1,
    cores: [{ key: K1, maxStorageBytes: 777, pinnedAt: 5, lastServedAt: 9 }, K2, 'not-a-key', { key: 'zz' }]
  }))
  const { store, swarm, requested } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()
  t.alike(requested.sort(), [K1, K2].sort(), 'invalid entries skipped')
  t.is(s.cores.get(K1).maxStorageBytes, 777)
  t.is(s.cores.get(K1).lastServedAt, 9)
  await s.stop()
})

test('ENOSPC during a persist leaves the previous file intact (atomic tmp+rename)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path })
  await s.start()
  await s.seedCore(K1)
  await s._persistTail
  const before = await readFile(path, 'utf8')

  const errors = []
  s.on('persist-error', (err) => errors.push(err))
  s._writeTmp = async (tmp) => {
    await writeFile(tmp, '{"schemaVersion":1,"cor') // partial write, then the disk fills
    const err = new Error('ENOSPC: no space left on device')
    err.code = 'ENOSPC'
    throw err
  }
  await s.seedCore(K2)
  await s._persistTail

  t.is(errors.length, 1, 'persist-error surfaced')
  t.is(errors[0].code, 'ENOSPC')
  t.is(await readFile(path, 'utf8'), before, 'previous file untouched — never missing or truncated')
  await t.exception(readFile(path + '.tmp', 'utf8'), /ENOENT/, 'partial tmp file cleaned up')
  await s.stop()
})

test('restore: a bound drop mid-restore never forgets pins not yet restored', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  // K1 restores over its persisted bound (dropped + purged; its unseed
  // persists mid-restore); K3's core fails to open (a damaged core).
  await writeFile(path, JSON.stringify({
    schemaVersion: 1,
    cores: [K1, K3, K2],
    pins: [
      { key: K1, maxStorageBytes: 100, group: GROUP, source: 'seed-request', pinnedAt: 1, lastServedAt: 0 },
      { key: K3, maxStorageBytes: null, group: null, source: 'legacy', pinnedAt: 0, lastServedAt: 0 },
      { key: K2, maxStorageBytes: null, group: null, source: 'local', pinnedAt: 2, lastServedAt: 0 }
    ]
  }))

  const purged = []
  const store = {
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      const core = fakeCore(hex)
      if (hex === K1) {
        core.length = 10
        core.byteLength = 1000
        core.purge = async () => { purged.push(hex) }
      }
      if (hex === K3) core.ready = async () => { throw new Error('DECODING_ERROR') }
      return core
    }
  }
  const s = new Seeder(store, { join () {}, async leave () {} }, { storagePath: path })
  const dropped = []
  s.on('core-bound-exceeded', (e) => dropped.push(e.publicKeyHex))
  await s.start()
  await s._persistTail

  t.alike(dropped, [K1], 'over-bound pin dropped at restore')
  t.alike(purged, [K1], 'and purged')
  t.ok(s.cores.has(K2), 'later pin still restored')
  const data = await readFileJson(path)
  t.alike(data.cores.sort(), [K2, K3].sort(), 'K1 forgotten; K3 (failed to open) carried for a retry; K2 kept')
  await s.stop()
})
