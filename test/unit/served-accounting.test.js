/**
 * ServedAccounting — honest outbound (served) byte counting.
 *
 * The bug it fixes: seeder.totalBytesServed only sums uploads from cores
 * routed through Seeder.seedCore. On a registry-drive relay that's just the
 * registry log core, so the counter reads ~0 while the relay actively serves
 * app blocks over corestore-level store.replicate(conn). ServedAccounting
 * attaches an 'upload' listener to EVERY core the corestore opens, so it
 * counts the real served total.
 *
 * These tests use real corestore<->corestore replication (no mocks) so they
 * exercise the actual hypercore 'upload' event the production code relies on.
 */

import test from 'brittle'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { EventEmitter } from 'events'
import Corestore from 'corestore'
import b4a from 'b4a'
import { ServedAccounting } from 'p2p-hiverelay/core/relay-node/served-accounting.js'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'served-accounting-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

// Pipe two corestores together and pull every block of `key` into the client,
// returning the total payload bytes the client downloaded.
async function replicateAndPull (serverStore, clientStore, key) {
  const s1 = serverStore.replicate(true)
  const s2 = clientStore.replicate(false)
  s1.pipe(s2).pipe(s1)

  const clientCore = clientStore.get({ key })
  await clientCore.ready()
  await clientCore.update({ wait: true })

  let downloaded = 0
  for (let i = 0; i < clientCore.length; i++) {
    const block = await clientCore.get(i)
    downloaded += block.byteLength
  }

  await clientCore.close()
  s1.destroy()
  s2.destroy()
  return downloaded
}

test('counts bytes served from a core created BEFORE start() (existing-core sweep)', async (t) => {
  const a = tmpDir(); const b = tmpDir()
  t.teardown(a.cleanup); t.teardown(b.cleanup)

  const server = new Corestore(a.dir)
  await server.ready()

  // Core exists and is open before the accountant starts — must still be
  // tracked via the start-time store.cores sweep.
  const core = server.get({ name: 'served-pre' })
  await core.ready()
  const payload = b4a.from('x'.repeat(4096))
  await core.append([payload, payload, payload])

  const served = new ServedAccounting({ store: server })
  served.start()

  const client = new Corestore(b.dir)
  await client.ready()
  const downloaded = await replicateAndPull(server, client, core.key)

  t.ok(downloaded > 0, 'client actually downloaded blocks')
  t.is(served.totalBytesServed, downloaded, 'served total equals what the client received')
  t.is(served.totalBlocksServed, 3, 'counted three served blocks')

  served.stop()
  await client.close()
  await server.close()
})

test('counts bytes served from a core created AFTER start() (core-open listener)', async (t) => {
  const a = tmpDir(); const b = tmpDir()
  t.teardown(a.cleanup); t.teardown(b.cleanup)

  const server = new Corestore(a.dir)
  await server.ready()

  const served = new ServedAccounting({ store: server })
  served.start()

  // Core opened AFTER the accountant started — must be picked up by the
  // store 'core-open' event, not the start-time sweep.
  const core = server.get({ name: 'served-post' })
  await core.ready()
  const payload = b4a.from('y'.repeat(2048))
  await core.append([payload, payload])

  const client = new Corestore(b.dir)
  await client.ready()
  const downloaded = await replicateAndPull(server, client, core.key)

  t.ok(downloaded > 0, 'client downloaded blocks from the post-start core')
  t.is(served.totalBytesServed, downloaded, 'served total equals what the client received')
  t.ok(served.getSummary().trackedCores >= 1, 'at least the served core is tracked')

  served.stop()
  await client.close()
  await server.close()
})

test('getSummary shape + stop() detaches and is idempotent', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  const server = new Corestore(a.dir)
  await server.ready()
  const served = new ServedAccounting({ store: server })
  served.start()

  const summary = served.getSummary()
  t.alike(Object.keys(summary).sort(), ['totalBlocksServed', 'totalBytesServed', 'trackedCores'], 'summary keys')
  t.is(summary.totalBytesServed, 0, 'starts at zero')

  served.stop()
  // A core opened after stop() must NOT be tracked (listener detached).
  const core = server.get({ name: 'after-stop' })
  await core.ready()
  t.is(served.getSummary().trackedCores, 0, 'no cores tracked after stop')

  // Second stop() is a no-op, not a throw.
  served.stop()
  t.pass('double stop() is safe')

  await server.close()
})

test('stop() removes per-core upload listeners before restart', async (t) => {
  const core = new EventEmitter()
  const store = new EventEmitter()
  store.cores = new Map([['core', core]])

  const served = new ServedAccounting({ store })
  served.start()
  t.is(core.listenerCount('upload'), 1, 'one upload listener attached')

  core.emit('upload', 0, 100)
  t.is(served.totalBytesServed, 100, 'initial upload counted')

  served.stop()
  t.is(core.listenerCount('upload'), 0, 'upload listener removed on stop')
  t.is(served.getSummary().trackedCores, 0, 'tracked core count reset on stop')

  served.start()
  t.is(core.listenerCount('upload'), 1, 'restart reattaches exactly one listener')
  core.emit('upload', 1, 50)
  t.is(served.totalBytesServed, 150, 'restart did not double-count upload')

  served.stop()
})

test('constructor requires a store', async (t) => {
  t.exception(() => new ServedAccounting({}), /store is required/, 'throws without a store')
})
