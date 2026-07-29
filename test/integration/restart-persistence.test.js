/**
 * Restart persistence integration test.
 *
 * Pins the regression class where a clean stop()/start() cycle (operator
 * restart, systemd SIGTERM, or in-process SelfHeal restart) silently lost
 * all seeded apps. Three coupled defects produced it:
 *
 *   1. stop() called unseedApp() on every app, which persisted a registry
 *      delete — erasing entries from disk.
 *   2. HyperGateway.close() threw (DriveCache isn't iterable), leaking the
 *      HTTP server so the next start() hit EADDRINUSE.
 *   3. start() recreates the corestore on restart, but the AppRegistry's
 *      Hyperbee still pointed at the closed old store, so reseed read
 *      nothing even when entries survived on disk.
 *
 * The contract these tests assert: apps seeded before a restart are still
 * seeded after it.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import Hyperdrive from 'hyperdrive'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

async function makeNode (dir, bootstrap, extra = {}) {
  await mkdir(dir, { recursive: true })
  return new RelayNode({
    storage: dir,
    bootstrapNodes: bootstrap,
    enableAPI: false,
    enableRelay: false,
    enableSeeding: true,
    enableServices: false,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    shutdownTimeoutMs: 10_000,
    ...extra
  })
}

async function within (promise, timeoutMs, label) {
  let timer = null
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' timed out after ' + timeoutMs + 'ms')), timeoutMs)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function waitFor (fn, timeoutMs = 30_000, intervalMs = 50) {
  const startedAt = Date.now()
  while (Date.now() - startedAt < timeoutMs) {
    if (await fn()) return true
    await sleep(intervalMs)
  }
  return false
}

function hasCompletePinnedProof (entry) {
  return entry?.anchored === true &&
    entry.anchoredLength === entry.storageProvedDriveVersion &&
    Number.isSafeInteger(entry.storageProvedDriveVersion) && entry.storageProvedDriveVersion > 0 &&
    Number.isSafeInteger(entry.storageProvedMetaLength) && entry.storageProvedMetaLength >= 0 &&
    Number.isSafeInteger(entry.storageProvedBlobLength) && entry.storageProvedBlobLength >= 0 &&
    Number.isSafeInteger(entry.storageProvedTotalBytes) && entry.storageProvedTotalBytes >= 0 &&
    Number.isSafeInteger(entry.storageProvedMetaFork) && entry.storageProvedMetaFork >= 0 &&
    Number.isSafeInteger(entry.storageProvedBlobFork) && entry.storageProvedBlobFork >= 0 &&
    Array.isArray(entry.downloadSnapshotCores) && entry.downloadSnapshotCores.length === 2
}

async function assertPinnedEntries (t, node, keys, label) {
  for (const key of keys) {
    t.ok(await waitFor(() => hasCompletePinnedProof(node.appRegistry.get(key))),
      `${label}: ${key.slice(0, 8)} has complete persisted proof + live snapshots`)
    t.is(node.appRegistry.get(key)?.maxStorage, TEST_MAX_STORAGE_BYTES,
      `${label}: ${key.slice(0, 8)} preserves exact finite bound`)
    t.ok(node.storageAdmission.canAcknowledge(`drive:${key}`),
      `${label}: ${key.slice(0, 8)} has authority ACK`)
  }
}

async function startPublisher (baseDir, bootstrap, count, label) {
  const publisher = await makeNode(join(baseDir, 'publisher'), bootstrap)
  const drives = []
  const discovery = []
  const keys = []
  await publisher.start()
  for (let i = 0; i < count; i++) {
    // namespace() is itself a Corestore session; a nested session loses the
    // namespace under Corestore 7 and deadlocks the second writable drive.
    const drive = new Hyperdrive(publisher.store.namespace(`${label}-${i}`))
    await drive.ready()
    await drive.put('/index.bin', randomBytes(64 * 1024))
    drives.push(drive)
    keys.push(b4a.toString(drive.key, 'hex'))
    discovery.push(publisher.swarm.join(drive.discoveryKey, { server: true, client: true }))
  }
  await publisher.swarm.flush()
  return { publisher, drives, discovery, keys }
}

async function stopPublisher (fixture) {
  for (const handle of fixture.discovery) {
    try { await handle.destroy() } catch {}
  }
  for (const drive of fixture.drives) {
    try { await drive.close() } catch {}
  }
  await fixture.publisher.stop()
}

async function seedAll (node, keys) {
  for (const key of keys) {
    await within(
      node.seedApp(key, { maxStorage: TEST_MAX_STORAGE_BYTES }),
      30_000,
      'authoritative seed ' + key.slice(0, 8)
    )
  }
}

test('seeded apps survive a stop()/start() cycle (in-process restart)', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-restart-${id}`)
  const dir = join(baseDir, 'consumer')
  const testnet = await createTestnet(2)
  const node = await makeNode(dir, testnet.bootstrap)
  let source = null

  t.teardown(async () => {
    try { await node.stop() } catch {}
    if (source) try { await stopPublisher(source) } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  source = await startPublisher(baseDir, testnet.bootstrap, 3, 'in-process')
  await node.start()
  t.is(new Set(source.keys).size, 3, 'publisher authored three distinct drive keys')
  await seedAll(node, source.keys)
  await assertPinnedEntries(t, node, source.keys, 'before in-process restart')
  t.is(node.seededApps.size, 3, 'three apps seeded before restart')

  await node.stop()
  await node.start()
  await assertPinnedEntries(t, node, source.keys, 'after in-process restart')
  t.is(node.seededApps.size, 3, 'all three apps repopulated after restart')
  for (const k of source.keys) {
    t.ok(node.seededApps.has(k), `app ${k.slice(0, 8)} present after restart`)
  }
})

test('apps survive a fresh-process restart (new RelayNode, same storage)', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-restart-fresh-${id}`)
  const dir = join(baseDir, 'consumer')
  const testnet = await createTestnet(2)

  let node = await makeNode(dir, testnet.bootstrap)
  let source = null
  t.teardown(async () => {
    try { await node.stop() } catch {}
    if (source) try { await stopPublisher(source) } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  source = await startPublisher(baseDir, testnet.bootstrap, 2, 'fresh-process')
  await node.start()
  t.is(new Set(source.keys).size, 2, 'publisher authored two distinct drive keys')
  await seedAll(node, source.keys)
  await assertPinnedEntries(t, node, source.keys, 'before fresh-process restart')
  await node.stop()

  // Simulate a process restart: brand-new RelayNode over the same storage.
  node = await makeNode(dir, testnet.bootstrap)
  await node.start()
  await assertPinnedEntries(t, node, source.keys, 'after fresh-process restart')
  t.is(node.seededApps.size, 2, 'apps reloaded by a fresh process from disk')
  for (const k of source.keys) {
    t.ok(node.seededApps.has(k), `app ${k.slice(0, 8)} reloaded by fresh process`)
  }
})
