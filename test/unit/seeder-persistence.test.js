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
import { mkdtemp, readFile } from 'fs/promises'
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
