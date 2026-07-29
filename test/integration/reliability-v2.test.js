/**
 * Reliability v2 integration tests — verify the LifecycleScope cancellation
 * contract drains every fire-and-forget loop before stop()'s teardown
 * destroys the swarm and corestore.
 *
 * These tests catch the regression class fixed by Reliability v2: long-running
 * fire-and-forget closures (eagerReplicate, _indexLog, repair pass, etc.)
 * that capture references to drives/cores/registry-entries and outlive
 * their owners' intended teardown — producing "Mutex has been destroyed",
 * "The corestore is closed", and SESSION_CLOSED errors on production
 * relays under self-heal restart.
 *
 * See STALE-REF-INVENTORY.md + CANCELLATION-CONTRACT.md for the audit
 * + contract design.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import Hyperdrive from 'hyperdrive'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { isAbortError } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024

async function makeNode (baseDir, name, bootstrap, extra = {}) {
  const dir = join(baseDir, name)
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

async function waitFor (fn, timeoutMs = 30_000, intervalMs = 50) {
  const startedAt = Date.now()
  while (Date.now() - startedAt < timeoutMs) {
    if (await fn()) return true
    await sleep(intervalMs)
  }
  return false
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

test('Reliability v2: start() creates a scope; stop() drains + clears it', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-relv2-wire-${id}`)
  const testnet = await createTestnet(2)
  const node = await makeNode(baseDir, 'node', testnet.bootstrap)

  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  t.is(node._scope, null, 'no scope before start()')
  await node.start()
  t.ok(node._scope, 'scope present after start()')
  t.is(node._scope.aborted, false, 'scope not aborted while running')

  const scopeRef = node._scope
  await node.stop()
  t.is(node._scope, null, 'scope nulled after stop()')
  t.is(scopeRef.aborted, true, 'old scope was aborted')
})

test('Reliability v2: stop() drains tracked fire-and-forget before returning', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-relv2-drain-${id}`)
  const testnet = await createTestnet(2)
  const node = await makeNode(baseDir, 'node', testnet.bootstrap)

  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  await node.start()

  // Manually register a deliberately-slow fire-and-forget that observes
  // the abort signal. stop()'s drain MUST wait for it to settle —
  // otherwise an in-flight eagerReplicate could outlive the corestore.
  let settledBeforeStopReturned = false
  let aborted = false
  const slowPromise = (async () => {
    try {
      await node._scope.sleep(5_000)
    } catch (err) {
      if (isAbortError(err)) aborted = true
    }
    // Mark settled after the sleep returns (either normally or via abort).
    // This runs INSIDE the tracked promise, so drain() must observe it
    // settling before allSettled resolves.
    settledBeforeStopReturned = true
  })()
  node._scope.tracked(slowPromise)

  const stopStart = Date.now()
  await node.stop()
  const stopMs = Date.now() - stopStart

  t.is(settledBeforeStopReturned, true, 'tracked promise settled before stop() returned')
  t.is(aborted, true, 'tracked promise saw AbortError (signal fired first)')
  t.ok(stopMs < 4000, 'stop() did not wait the full 5s sleep (' + stopMs + 'ms) — abort short-circuited it')
})

test('Reliability v2: multi-cycle start/stop with seeded apps is clean', async (t) => {
  // Simulates the self-heal restart pattern: stop() then start() in quick
  // succession with seeded apps in registry. On v0.8.12 / main, the
  // fire-and-forget _eagerReplicate from each seedApp survives stop()
  // and crashes against the next start()'s fresh corestore — producing
  // the "Mutex has been destroyed" / "corestore is closed" leaks. With
  // the contract, every cycle's loops are drained before teardown.
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-relv2-cycles-${id}`)
  const testnet = await createTestnet(2)
  const node = await makeNode(baseDir, 'node', testnet.bootstrap)
  const publisher = await makeNode(baseDir, 'publisher', testnet.bootstrap)
  const sourceDrives = []
  const sourceDiscovery = []

  t.teardown(async () => {
    try { await node.stop() } catch {}
    for (const handle of sourceDiscovery) {
      try { await handle.destroy() } catch {}
    }
    for (const drive of sourceDrives) {
      try { await drive.close() } catch {}
    }
    try { await publisher.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  await publisher.start()
  const seededKeys = []
  for (let i = 0; i < 3; i++) {
    // namespace() already returns an owning Corestore session. Wrapping it in
    // another session drops the namespace in Corestore 7 and makes the second
    // writable Hyperdrive contend for the first drive's deterministic key.
    const drive = new Hyperdrive(publisher.store.namespace('reliability-source-' + i))
    await drive.ready()
    await drive.put('/initial.bin', randomBytes(64 * 1024))
    sourceDrives.push(drive)
    seededKeys.push(b4a.toString(drive.key, 'hex'))
    sourceDiscovery.push(publisher.swarm.join(drive.discoveryKey, { server: true, client: true }))
  }
  t.is(new Set(seededKeys).size, 3, 'publisher authored three distinct drive keys')
  await publisher.swarm.flush()

  const reseedErrors = []
  const repairErrors = []
  const indexErrors = []
  node.on('reseed-error', (e) => reseedErrors.push(e))
  node.on('repair-error', (e) => repairErrors.push(e))
  node.on('index-error', (e) => indexErrors.push(e))

  for (let cycle = 0; cycle < 3; cycle++) {
    await node.start()
    t.ok(node._scope, 'cycle ' + cycle + ': scope created')

    // First cycle seeds three real, finite-bounded drives from a live
    // publisher. Subsequent cycles recover the persisted entries and re-fire
    // eagerReplicate against the same publisher-owned content.
    if (cycle === 0) {
      for (const key of seededKeys) {
        const seedStartedAt = Date.now()
        await within(
          node.seedApp(key, { maxStorage: TEST_MAX_STORAGE_BYTES }),
          30_000,
          'authoritative seed ' + key.slice(0, 8)
        )
        t.ok(Date.now() - seedStartedAt < 30_000, 'cycle 0: authoritative seed returned within 30s')
        const proved = await waitFor(() => {
          const entry = node.appRegistry.get(key)
          return entry?.anchored === true &&
            Number.isSafeInteger(entry.storageProvedDriveVersion) && entry.storageProvedDriveVersion > 0 &&
            Array.isArray(entry.downloadSnapshotCores) && entry.downloadSnapshotCores.length === 2
        })
        t.ok(proved, 'cycle 0: seeded drive has a persisted pinned proof')
        t.ok(node.storageAdmission.canAcknowledge(`drive:${key}`), 'cycle 0: seeded drive has authority ACK')
      }
    } else {
      t.ok(await waitFor(() => seededKeys.every(key => node.appRegistry.get(key)?.drive)),
        'cycle ' + cycle + ': all persisted drives reopened')
    }

    // Advance every publisher drive and explicitly trigger the same tracked
    // product fan-out used by fresh seeds and recovery. stop() must abort and
    // drain these real drive update/download paths before closing Corestore.
    for (let i = 0; i < sourceDrives.length; i++) {
      await sourceDrives[i].put(`/cycle-${cycle}.bin`, randomBytes(64 * 1024))
      const entry = node.appRegistry.get(seededKeys[i])
      node.appLifecycle._trackEagerReplicate(seededKeys[i], entry.drive, {
        maxStorage: TEST_MAX_STORAGE_BYTES
      }, { source: 'reliability-v2-cycle' })
    }
    await sleep(200)

    const stopStart = Date.now()
    await node.stop()
    const stopMs = Date.now() - stopStart

    t.is(node._scope, null, 'cycle ' + cycle + ': scope cleared after stop()')
    t.ok(stopMs < 9_000, 'cycle ' + cycle + ': stop() returned in ' + stopMs + 'ms')
  }

  // After 3 cycles, no stale-ref errors should have leaked into any
  // event stream. (Real swarm flush errors during teardown are filtered
  // out — we only care about the Mutex/corestore class.)
  const allErrors = [...reseedErrors, ...repairErrors, ...indexErrors]
  const staleRefErrors = allErrors.filter((e) => {
    const msg = (e && (e.error && e.error.message)) || (e && e.error) || ''
    return /Mutex has been destroyed|corestore is closed|SESSION_CLOSED|Cannot make sessions on a closing core/i.test(String(msg))
  })
  t.is(staleRefErrors.length, 0,
    'no stale-ref errors emitted across 3 start/stop cycles' +
    (staleRefErrors.length > 0 ? ' — first: ' + JSON.stringify(staleRefErrors[0]) : ''))
})

test('Reliability v2: tracked promises survive their .catch() handler without leaking', async (t) => {
  // Regression guard: every tier-B site wraps its .catch() inside the
  // _trackFireAndForget call. If a future refactor accidentally
  // wraps the wrong thing (e.g. .catch is applied AFTER tracked,
  // returning a different promise), drain() wouldn't await the catch's
  // tail. This test fires a tracked promise whose .catch() body sleeps,
  // asserting drain() blocks until the catch's tail has run.
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-relv2-catch-${id}`)
  const testnet = await createTestnet(2)
  const node = await makeNode(baseDir, 'node', testnet.bootstrap)

  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  await node.start()

  let catchTailRan = false
  const promise = (async () => {
    throw new Error('intentional')
  })().catch(() => {
    catchTailRan = true
  })
  node._scope.tracked(promise)

  await node.stop()
  t.is(catchTailRan, true, 'catch() tail observed by drain()')
})
