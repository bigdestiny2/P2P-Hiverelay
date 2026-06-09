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
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

function randomAppKey () {
  return b4a.toString(randomBytes(32), 'hex')
}

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

test('seeded apps survive a stop()/start() cycle (in-process restart)', async (t) => {
  const id = randomBytes(4).toString('hex')
  const dir = join(tmpdir(), `hiverelay-restart-${id}`)
  const testnet = await createTestnet(2)
  const node = await makeNode(dir, testnet.bootstrap)

  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(dir, { recursive: true, force: true }) } catch {}
  })

  await node.start()

  const keys = []
  for (let i = 0; i < 3; i++) {
    const k = randomAppKey()
    keys.push(k)
    await node.seedApp(k, {})
  }
  await sleep(200)
  t.is(node.seededApps.size, 3, 'three apps seeded before restart')

  await node.stop()
  await node.start()
  // reseedFromRegistry is a tracked fire-and-forget kicked off during
  // start(); give it a beat to load from disk and re-seed.
  await sleep(500)

  t.is(node.seededApps.size, 3, 'all three apps repopulated after restart')
  for (const k of keys) {
    t.ok(node.seededApps.has(k), `app ${k.slice(0, 8)} present after restart`)
  }
})

test('apps survive a fresh-process restart (new RelayNode, same storage)', async (t) => {
  const id = randomBytes(4).toString('hex')
  const dir = join(tmpdir(), `hiverelay-restart-fresh-${id}`)
  const testnet = await createTestnet(2)

  let node = await makeNode(dir, testnet.bootstrap)
  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(dir, { recursive: true, force: true }) } catch {}
  })

  await node.start()
  const keys = []
  for (let i = 0; i < 2; i++) {
    const k = randomAppKey()
    keys.push(k)
    await node.seedApp(k, {})
  }
  await sleep(200)
  await node.stop()

  // Simulate a process restart: brand-new RelayNode over the same storage.
  node = await makeNode(dir, testnet.bootstrap)
  await node.start()
  await sleep(500)

  t.is(node.seededApps.size, 2, 'apps reloaded by a fresh process from disk')
  for (const k of keys) {
    t.ok(node.seededApps.has(k), `app ${k.slice(0, 8)} reloaded by fresh process`)
  }
})
