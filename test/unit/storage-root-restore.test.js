/**
 * storage-root-restore (openCorestore) — corestore 7 migration guard.
 *
 * hypercore-storage 3 (corestore 7) runs a one-time tmpFixStorage the first
 * time it opens a pre-7 storage root: every top-level entry that isn't
 * corestore-owned is moved into db/. The relay keeps its own state files in
 * the same root (app-registry.json, federation.json, …) — openCorestore()
 * must put back whatever the sweep relocated, or an upgrading relay boots
 * with an "empty" registry and forgets what it seeds.
 */

import test from 'brittle'
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { openCorestore } from '../../packages/core/core/persistence/storage-root-restore.js'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'storage-root-restore-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

test('pre-7 root: foreign state files survive the layout sweep at the root', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  // Simulate a v0.24.x (corestore 6-era) relay root: app state next to cores.
  writeFileSync(join(a.dir, 'app-registry.json'), JSON.stringify([{ appKey: 'a'.repeat(64) }]))
  writeFileSync(join(a.dir, 'federation.json'), JSON.stringify({ follows: ['https://peer.example'] }))

  const store = openCorestore(a.dir)
  await store.ready()

  t.ok(existsSync(join(a.dir, 'CORESTORE')), 'corestore 7 marker written')
  t.ok(existsSync(join(a.dir, 'app-registry.json')), 'app-registry.json restored to root')
  t.ok(existsSync(join(a.dir, 'federation.json')), 'federation.json restored to root')
  t.is(JSON.parse(readFileSync(join(a.dir, 'app-registry.json'), 'utf8'))[0].appKey, 'a'.repeat(64), 'content intact')

  // The store is fully usable after the restore.
  const core = store.get({ name: 'probe' })
  await core.ready()
  await core.append(['block'])
  t.is(await core.length, 1, 'core append/read works on the guarded root')

  await store.close()
})

test('fresh root: opens cleanly with nothing to restore', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  const store = openCorestore(a.dir)
  await store.ready()
  const core = store.get({ name: 'fresh' })
  await core.ready()
  await core.append(['x'])
  t.is(await core.length, 1, 'fresh store works')
  t.ok(existsSync(join(a.dir, 'CORESTORE')), 'marker written on first open')

  await store.close()
})

test('second open (marker present): no sweep, root files untouched', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  const first = openCorestore(a.dir)
  await first.ready()
  await first.close()

  // Operator drops a new state file into an already-migrated (marker-present) root.
  writeFileSync(join(a.dir, 'services.json'), JSON.stringify({ outboxlog: true }))

  const second = openCorestore(a.dir)
  await second.ready()
  t.ok(existsSync(join(a.dir, 'services.json')), 'marker-present root is never swept')
  t.is(JSON.parse(readFileSync(join(a.dir, 'services.json'), 'utf8')).outboxlog, true, 'content intact')
  await second.close()
})
