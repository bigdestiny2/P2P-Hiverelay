// app-registry-hyperbee: v0.8.25 regression tests for the Hyperbee-
// backed persistence layer in AppRegistry. Replaces the JSON-blob
// rewrite-on-every-mutation model with single-block bee.put per
// mutation. Same public API surface; persistence is internal.
//
// Tests:
//   1. Bee mode boots cleanly with no existing JSON file
//   2. Bee mode boots cleanly with existing JSON file → migrates to bee
//   3. set/update/delete/setAnchored persist + survive restart
//   4. Concurrent mutations don't corrupt the bee
//   5. Legacy JSON mode still works (no setStore call)

import test from 'brittle'
import { mkdtemp, rm, readFile, writeFile, access } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import Corestore from 'corestore'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { admitPublicHiveAppEntry } from 'p2p-hiverelay/gateway/public-app-admission.js'

async function freshTmp () {
  return mkdtemp(join(tmpdir(), 'hiverelay-app-reg-bee-'))
}

async function exists (path) {
  try { await access(path); return true } catch { return false }
}

test('bee mode: empty start, set, restart preserves entries', async (t) => {
  const dir = await freshTmp()
  try {
    const appKey = 'a'.repeat(64)

    // Phase 1 — fresh registry, set one entry
    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      await reg.load()
      reg.set(appKey, {
        type: 'app',
        appId: 'pearpaste',
        version: '0.1.0',
        publisherPubkey: 'b'.repeat(64),
        durability: 1,
        revocable: false
      })
      await reg.flush()
      await store.close()
    }

    // Phase 2 — fresh AppRegistry on same corestore, expect entry restored
    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      const entries = await reg.load()
      t.is(reg.size, 1, 'one entry restored')
      t.is(reg.get(appKey).appId, 'pearpaste')
      t.is(reg.get(appKey).publisherPubkey, 'b'.repeat(64))
      t.is(reg.get(appKey).durability, 1)
      t.is(reg.get(appKey).revocable, false)
      t.is(entries.length, 1, 'load returns one reseed entry')
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: migrates existing JSON on first load', async (t) => {
  const dir = await freshTmp()
  try {
    const jsonPath = join(dir, 'app-registry.json')
    const bakPath = join(dir, 'app-registry.json.bak')

    // Pre-create a JSON file with two entries (legacy v0.8.24 format)
    await writeFile(jsonPath, JSON.stringify([
      {
        appKey: 'a'.repeat(64),
        appId: 'app-one',
        type: 'app',
        version: '1.0.0',
        blind: false,
        publisherPubkey: 'p'.repeat(64),
        durability: 0,
        revocable: true
      },
      {
        appKey: 'b'.repeat(64),
        appId: 'app-two',
        type: 'drive',
        version: '2.0.0',
        blind: true,
        retainUntil: Date.now() + 60_000
      }
    ], null, 2))

    const store = new Corestore(dir)
    await store.ready()
    const reg = new AppRegistry(dir, { store })

    let migrateEvent = null
    reg.on('migrated', (e) => { migrateEvent = e })

    const entries = await reg.load()

    t.ok(migrateEvent, 'migrated event fired')
    t.is(migrateEvent.count, 2, 'both entries migrated')
    t.is(migrateEvent.source, 'json')
    t.is(migrateEvent.target, 'hyperbee')

    t.is(reg.size, 2, 'both entries in memory')
    t.is(reg.get('a'.repeat(64)).appId, 'app-one')
    t.is(reg.get('b'.repeat(64)).appId, 'app-two')
    t.is(reg.get('b'.repeat(64)).blind, true)
    t.is(entries.length, 2, 'reseed list has both')

    const legacyPublic = reg.get('a'.repeat(64))
    t.is(legacyPublic.privacyTier, 'public', 'legacy hydration retains its compatibility default')
    t.is(legacyPublic.storageClass, 'persistent', 'legacy hydration retains its storage default')
    t.is(legacyPublic.availabilityClass, 'always-on', 'legacy hydration retains its availability default')
    t.alike(admitPublicHiveAppEntry(legacyPublic, {
      appKey: 'a'.repeat(64),
      publicAppKeys: []
    }), {
      allowed: false,
      reason: 'not-operator-approved'
    }, 'hydrated defaults cannot independently publish a legacy row')

    // JSON file renamed to .bak, bee now authoritative
    t.absent(await exists(jsonPath), 'app-registry.json renamed')
    t.ok(await exists(bakPath), 'app-registry.json.bak present')

    await store.close()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: mutations persist across restart (set, setAnchored, delete)', async (t) => {
  const dir = await freshTmp()
  try {
    const keepKey = 'a'.repeat(64)
    const deleteKey = 'b'.repeat(64)

    // Phase 1
    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      await reg.load()
      reg.set(keepKey, { type: 'app', appId: 'keep-me', maxStorage: 4096 })
      reg.set(deleteKey, { type: 'app', appId: 'delete-me' })
      reg.update(keepKey, {
        anchored: true,
        anchoredLength: 100,
        storageProvedDriveVersion: 100,
        storageProvedMetaLength: 1,
        storageProvedBlobLength: 0,
        storageProvedTotalBytes: 0,
        storageProvedMetaFork: 0,
        storageProvedBlobFork: 0
      })
      await reg.flush()
      reg.delete(deleteKey)
      await reg.flush()
      await store.close()
    }

    // Phase 2 — restart
    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      await reg.load()
      t.is(reg.size, 1, 'only keep-me survived')
      t.ok(reg.has(keepKey))
      t.absent(reg.has(deleteKey), 'deleted entry gone after restart')
      const restored = reg.get(keepKey)
      t.is(restored.anchored, true, 'setAnchored persisted')
      t.is(restored.anchoredLength, 100, 'anchoredLength persisted')
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('legacy JSON mode: still works when no store is passed', async (t) => {
  const dir = await freshTmp()
  try {
    const appKey = 'c'.repeat(64)

    // Phase 1 — no store, classic JSON path
    {
      const reg = new AppRegistry(dir)
      await reg.load()
      reg.set(appKey, { type: 'app', appId: 'legacy', version: '1.0.0' })
      await reg.flush()
    }

    // Phase 2 — read back via raw JSON to confirm legacy path persisted
    const jsonText = await readFile(join(dir, 'app-registry.json'), 'utf8')
    const parsed = JSON.parse(jsonText)
    t.is(parsed.length, 1)
    t.is(parsed[0].appId, 'legacy')

    // Phase 3 — new AppRegistry, no store, reads the same JSON file
    {
      const reg = new AppRegistry(dir)
      await reg.load()
      t.is(reg.size, 1)
      t.is(reg.get(appKey).appId, 'legacy')
      t.alike(admitPublicHiveAppEntry(reg.get(appKey), {
        appKey,
        publicAppKeys: []
      }), {
        allowed: false,
        reason: 'not-operator-approved'
      }, 'legacy JSON hydration remains private without local key approval')
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: setStore after load() throws', async (t) => {
  const dir = await freshTmp()
  try {
    const store = new Corestore(dir)
    await store.ready()
    const reg = new AppRegistry(dir, { store })
    await reg.load()

    const store2 = new Corestore(dir + '-other')
    await store2.ready()
    t.exception(() => reg.setStore(store2), /setStore must be called before load/)

    await store.close()
    await store2.close()
    await rm(dir + '-other', { recursive: true, force: true })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: concurrent set + delete of different keys both persist', async (t) => {
  const dir = await freshTmp()
  try {
    const keyA = 'a'.repeat(64)
    const keyB = 'b'.repeat(64)
    const keyC = 'c'.repeat(64)

    const store = new Corestore(dir)
    await store.ready()
    const reg = new AppRegistry(dir, { store })
    await reg.load()

    reg.set(keyA, { type: 'app', appId: 'a' })
    reg.set(keyB, { type: 'app', appId: 'b' })
    reg.set(keyC, { type: 'app', appId: 'c' })
    reg.delete(keyB)

    await reg.flush()
    await store.close()

    const store2 = new Corestore(dir)
    await store2.ready()
    const reg2 = new AppRegistry(dir, { store: store2 })
    await reg2.load()

    t.is(reg2.size, 2, 'A and C survived; B deleted')
    t.ok(reg2.has(keyA))
    t.absent(reg2.has(keyB), 'B deleted')
    t.ok(reg2.has(keyC))

    await store2.close()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: low-debt tombstone re-add reuses history and survives restart', async (t) => {
  const dir = await freshTmp()
  const key = 'd'.repeat(64)
  try {
    let finalDebt = 0
    let finalBytes = 0
    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      await reg.load()
      reg.set(key, { type: 'drive', appId: 'readd-ok', maxStorage: 4096 }, { persist: false })
      await reg.persistEntry(key, { throwOnError: true })
      const firstDebt = reg._metadataBudgets.get(key).bytes

      reg.delete(key, { persist: false })
      await reg.persistDelete(key, { throwOnError: true })
      const retiredDebt = reg._metadataBudgets.get(key).bytes
      t.ok(retiredDebt > firstDebt)

      reg.set(key, { type: 'drive', appId: 'readd-ok', version: '2.0.0', maxStorage: 4096 }, { persist: false })
      await reg.persistEntry(key, { throwOnError: true })
      finalDebt = reg._metadataBudgets.get(key).bytes
      finalBytes = reg._bee.core.byteLength
      t.ok(finalDebt > retiredDebt, 're-add adopts rather than resets tombstone debt')
      t.ok(finalDebt < 48 * 1024, 'normal low-debt re-add retains retirement reserve')
      await store.close()
    }

    {
      const store = new Corestore(dir)
      await store.ready()
      const reg = new AppRegistry(dir, { store })
      const entries = await reg.load()
      t.is(entries.length, 1)
      t.is(reg.get(key).version, '2.0.0')
      t.is(reg._metadataBudgets.get(key).bytes, finalDebt)
      t.is(reg._bee.core.byteLength, finalBytes)
      t.ok(reg._bee.core.byteLength <= reg._registryJournal.baselineBytes + 64 * 1024)
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('bee mode: empty JSON file is still migrated cleanly', async (t) => {
  const dir = await freshTmp()
  try {
    const jsonPath = join(dir, 'app-registry.json')
    await writeFile(jsonPath, '[]') // empty array

    const store = new Corestore(dir)
    await store.ready()
    const reg = new AppRegistry(dir, { store })
    const entries = await reg.load()

    t.is(reg.size, 0)
    t.is(entries.length, 0)
    // Empty file should still be renamed to .bak so we don't try to migrate again
    t.absent(await exists(jsonPath))
    t.ok(await exists(jsonPath + '.bak'))

    await store.close()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
