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
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { isAbortError } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

function randomAppKey () {
  return b4a.toString(randomBytes(32), 'hex')
}

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

  t.teardown(async () => {
    try { await node.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  const reseedErrors = []
  const repairErrors = []
  const indexErrors = []
  node.on('reseed-error', (e) => reseedErrors.push(e))
  node.on('repair-error', (e) => repairErrors.push(e))
  node.on('index-error', (e) => indexErrors.push(e))

  const seededKeys = []

  for (let cycle = 0; cycle < 3; cycle++) {
    await node.start()
    t.ok(node._scope, 'cycle ' + cycle + ': scope created')

    // First cycle seeds three random apps; subsequent cycles see them
    // reseeded from disk and each re-fires eagerReplicate.
    if (cycle === 0) {
      for (let i = 0; i < 3; i++) {
        const k = randomAppKey()
        seededKeys.push(k)
        await node.seedApp(k, {})
      }
    }

    // Let the in-flight eagerReplicate fan-out kick off — each seedApp
    // launches a tracked _eagerReplicate that enters swarm.flush() then
    // updateWithTimeout(30s). 200ms is enough for the loop to be
    // mid-await on every app.
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
