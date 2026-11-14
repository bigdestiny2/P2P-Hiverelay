/**
 * Client storage-root restore — corestore 7 migration guard on the SDK path.
 *
 * Mirrors test/unit/storage-root-restore.test.js, but for HiveRelayClient
 * rather than the relay. The client keeps four durable sidecars at the top
 * level of its storage root — forks.json, pending-seeds.json,
 * app-drives.json and bootstrap-cache.json — which is exactly the level
 * Corestore 7 sweeps into db/ the first time it opens a pre-7 root.
 *
 * Every one of those loaders treats a missing file as "start fresh", so an
 * unguarded upgrade loses fork quarantines, the seed retry queue, the
 * app->drive map and cached peers without surfacing a single error. These
 * tests therefore assert on what the client actually LOADED, not merely on
 * where the files ended up.
 */

import test from 'brittle'
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'fs'
import { join, basename, dirname } from 'path'
import { tmpdir } from 'os'
import { ForkDetector } from 'p2p-hiverelay/core/fork-detector.js'
import { BootstrapCache } from 'p2p-hiverelay/core/bootstrap-cache.js'
import { HiveRelayClient } from 'p2p-hiverelay-client'

const DRIVE_KEY = 'a'.repeat(64)
const FORKED_KEY = 'c'.repeat(64)

// Loopback-only so a started client never emits a packet off the machine.
const BOOTSTRAP = [{ host: '127.0.0.1', port: 49737 }]
const CACHED_PEER = { host: '127.0.0.1', port: 49738, lastSeen: 1 }
const LEARNED_PEER = { host: '127.0.0.1', port: 49739 }

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'client-storage-root-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

function stageDir (storage) {
  return join(dirname(storage), `${basename(storage)}.hiverelay-corestore7-state`)
}

async function startClient (t, dir) {
  const client = new HiveRelayClient({ storage: dir, bootstrap: BOOTSTRAP, autoDiscover: false })
  t.teardown(() => client.destroy())
  await client.start()
  return client
}

// Writes a genuine forks.json through ForkDetector itself, so the fixture
// carries the real schemaVersion rather than a hand-rolled guess.
async function seedForkRecord (dir) {
  const detector = new ForkDetector({ storagePath: join(dir, 'forks.json') })
  const reported = detector.report({
    hypercoreKey: FORKED_KEY,
    blockIndex: 4,
    evidenceA: { fromRelay: 'relay-a', block: 'aa', signature: '11' },
    evidenceB: { fromRelay: 'relay-b', block: 'bb', signature: '22' }
  })
  if (!reported.ok) throw new Error(`fixture fork report rejected: ${reported.reason}`)
  await detector.save()
}

async function seedLegacyRoot (dir) {
  await seedForkRecord(dir)
  writeFileSync(join(dir, 'pending-seeds.json'), JSON.stringify([{ appKey: DRIVE_KEY, opts: {}, attempts: 2 }]))
  writeFileSync(join(dir, 'app-drives.json'), JSON.stringify({ 'my-app': DRIVE_KEY }))
  writeFileSync(join(dir, 'bootstrap-cache.json'), JSON.stringify({ peers: [CACHED_PEER] }))
}

test('pre-7 client root: all four sidecars survive and the client still loads them', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)
  await seedLegacyRoot(a.dir)

  // Capture the exact loaded state before connections can extend the cache.
  // Then exercise the real cache connection callback during client startup:
  // learning another peer must not make preservation depend on cache length.
  let loadedPeers
  const cacheStart = BootstrapCache.prototype.start
  BootstrapCache.prototype.start = function (swarm) {
    loadedPeers = this._peers.map(peer => ({ ...peer }))
    const result = cacheStart.call(this, swarm)
    this._connectionHandler({
      rawStream: { remoteHost: LEARNED_PEER.host, remotePort: LEARNED_PEER.port }
    })
    return result
  }
  let client
  try {
    client = await startClient(t, a.dir)
  } finally {
    BootstrapCache.prototype.start = cacheStart
  }

  t.ok(existsSync(join(a.dir, 'CORESTORE')), 'corestore 7 marker written')
  for (const name of ['forks.json', 'pending-seeds.json', 'app-drives.json', 'bootstrap-cache.json']) {
    t.ok(existsSync(join(a.dir, name)), `${name} restored to root`)
    t.absent(existsSync(join(a.dir, 'db', name)), `${name} not stranded in db/`)
  }

  // The point of the guard: the client's own state survived, not just the bytes.
  t.ok(client.forkDetector.isQuarantined(FORKED_KEY), 'fork quarantine survived the upgrade')
  t.is(client._pendingSeeds.size, 1, 'seed retry queue survived the upgrade')
  t.is(client._pendingSeeds.get(DRIVE_KEY)?.attempts, 2, 'queue entry kept its retry count')
  t.is(await client._loadAppDriveMapping('my-app'), DRIVE_KEY, 'app->drive mapping survived the upgrade')
  t.alike(loadedPeers, [CACHED_PEER], 'the exact cached peer state was loaded before learning')
  t.alike(client._bootstrapCache._peers.find(peer => peer.host === CACHED_PEER.host && peer.port === CACHED_PEER.port), CACHED_PEER, 'cached peer remains intact after learning')
  t.ok(client._bootstrapCache._peers.some(peer => peer.host === LEARNED_PEER.host && peer.port === LEARNED_PEER.port), 'a newly learned peer coexists with the restored peer')

  // Migration bookkeeping is fully retired once the restore completes.
  t.absent(existsSync(stageDir(a.dir)), 'staging directory removed after restore')

  // The store is usable afterwards.
  const core = client.store.get({ name: 'probe' })
  await core.ready()
  await core.append(['block'])
  t.is(core.length, 1, 'core append works on the guarded root')
})

test('fresh client root: starts cleanly with nothing to restore', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  const client = await startClient(t, a.dir)

  t.ok(existsSync(join(a.dir, 'CORESTORE')), 'marker written on first start')
  t.is(client._pendingSeeds.size, 0, 'no phantom queue entries on a fresh root')
  t.absent(existsSync(stageDir(a.dir)), 'no staging directory left behind')
})

test('already-migrated client root: a later start never sweeps sidecars again', async (t) => {
  const a = tmpDir()
  t.teardown(a.cleanup)

  const first = new HiveRelayClient({ storage: a.dir, bootstrap: BOOTSTRAP, autoDiscover: false })
  await first.start()
  await first.destroy()
  t.ok(existsSync(join(a.dir, 'CORESTORE')), 'first start migrated the root')

  // Sidecars written by a running client land in a marker-present root.
  await seedLegacyRoot(a.dir)

  const second = await startClient(t, a.dir)

  for (const name of ['forks.json', 'pending-seeds.json', 'app-drives.json', 'bootstrap-cache.json']) {
    t.ok(existsSync(join(a.dir, name)), `${name} untouched in a marker-present root`)
  }
  t.is(JSON.parse(readFileSync(join(a.dir, 'app-drives.json'), 'utf8'))['my-app'], DRIVE_KEY, 'content intact')
  t.ok(second.forkDetector.isQuarantined(FORKED_KEY), 'fork quarantine readable across restarts')
})
