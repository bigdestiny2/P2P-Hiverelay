/**
 * BareRelay surface smoke test.
 *
 * We cannot exercise BareRelay end-to-end under Node because the file
 * declares imports for `bare-events`, `bare-fs/promises`, `bare-path` which
 * the package.json `imports` map redirects to Node built-ins under the
 * `default` condition. This test verifies that:
 *
 *   1. The BareRelay module loads at all under Node (no missing deps,
 *      no broken exports map).
 *   2. The class has the API surface the Pear runtime expects.
 *   3. Shared accept-mode helpers behave identically in BareRelay and
 *      RelayNode — this matters because both runtimes apply the same
 *      policy module and a divergence would silently break parity.
 *
 * End-to-end testing of the actual Bare runtime path requires running under
 * `bare` or `pear run` and is covered by manual operator verification, not
 * this suite.
 */

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readFile, rm, stat } from 'fs/promises'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { join } from 'path'
import { tmpdir } from 'os'
import { BareRelay } from 'p2p-hiverelay/core/relay-node/bare-relay.js'
import { sharedOperationFlights } from 'p2p-hiverelay/core/shared-flight-registry.js'
import { createCanonicalCatalogRow } from 'p2p-hiverelay/core/relay-node/app-catalog-paged.js'

function tmpStorage () {
  return join(tmpdir(), 'hiverelay-bare-identity-' + randomBytes(8).toString('hex'))
}

function deferred () {
  let resolvePromise
  const promise = new Promise(resolve => { resolvePromise = resolve })
  return { promise, resolve: resolvePromise }
}

function catalogKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function signedLegacyCatalog (apps, keyPair, catalogTimestamp = Date.now(), extras = {}) {
  const relayPubkey = b4a.toString(keyPair.publicKey, 'hex')
  const signable = b4a.from(JSON.stringify({ apps, relayPubkey, catalogTimestamp }), 'utf8')
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signable, keyPair.secretKey)
  return {
    apps,
    relayPubkey,
    catalogTimestamp,
    signature: b4a.toString(signature, 'hex'),
    remotePubkey: relayPubkey,
    ...extras
  }
}

function boundedAppRegistry (apps, extras = {}) {
  let cycleKeys = null
  let position = 0
  return {
    apps,
    page (consumer, budget) {
      if (consumer !== 'bare-shutdown') throw new Error('unexpected population consumer')
      if (cycleKeys === null) cycleKeys = [...apps.keys()]
      const entries = []
      let examined = 0
      while (position < cycleKeys.length && examined < budget) {
        const key = cycleKeys[position++]
        examined++
        if (apps.has(key)) entries.push({ key, value: apps.get(key) })
      }
      const complete = position >= cycleKeys.length
      if (complete) {
        cycleKeys = null
        position = 0
      }
      return { entries, examined, complete }
    },
    releasePopulationConsumer (consumer) {
      if (consumer !== 'bare-shutdown') throw new Error('unexpected population consumer')
      cycleKeys = null
      position = 0
      return true
    },
    ...extras
  }
}

test('bare lifecycle: concurrent start callers share one exact completion authority', async (t) => {
  const gate = deferred()
  const relay = Object.create(BareRelay.prototype)
  Object.assign(relay, {
    running: false,
    _starting: false,
    _stopping: null,
    _startCompletion: null,
    async _startLifecycle () {
      await gate.promise
      this.running = true
      return this
    }
  })

  const first = relay.start()
  const concurrent = relay.start()
  t.is(concurrent, first, 'concurrent Bare caller receives the exact first promise')
  gate.resolve()
  t.is(await first, relay, 'shared completion resolves to the exact Bare relay')
  t.is(relay.start(), first, 'already-running Bare start returns the completed authority')

  const failureGate = deferred()
  const failure = new Error('injected bare startup failure')
  const failing = Object.create(BareRelay.prototype)
  Object.assign(failing, {
    running: false,
    _starting: false,
    _stopping: null,
    _startCompletion: null,
    async _startLifecycle () {
      await failureGate.promise
      throw failure
    }
  })
  const rejectedFirst = failing.start()
  const rejectedConcurrent = failing.start()
  t.is(rejectedConcurrent, rejectedFirst, 'rejected Bare callers share exact promise')
  failureGate.resolve()
  let observed = null
  try { await rejectedConcurrent } catch (err) { observed = err }
  t.is(observed, failure, 'shared Bare rejection preserves exact startup error')
})

test('bare smoke: BareRelay module imports cleanly under Node via the imports map', (t) => {
  t.ok(BareRelay, 'BareRelay class is exported')
  t.is(typeof BareRelay, 'function', 'is a constructor')
})

test('bare smoke: BareRelay constructs with minimal config', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-smoke-' + Date.now() })
  t.ok(relay, 'instance constructed')
  t.is(relay.running, false, 'not running before start()')
  t.is(typeof relay.start, 'function', 'has start')
  t.is(typeof relay.stop, 'function', 'has stop')
  t.is(typeof relay._resolveAcceptMode, 'function', 'shares accept-mode resolver with RelayNode')
  t.is(typeof relay._decideAcceptance, 'function', 'shares accept-mode decision with RelayNode')
})

test('bare smoke: default config matches Bare-appropriate defaults', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-smoke-' + Date.now() })
  // Bare has no operator TUI to drain a review queue, so the default mode
  // must NOT be 'review' or every inbound seed would block forever.
  t.is(relay.config.acceptMode, 'open', 'Bare default is open (Pear operator opts into tighter modes explicitly)')
  t.is(relay.config.enableSeeding, true)
  t.is(relay.config.enableRelay, true)
  t.is(relay.config.catalogSync, true)
})

test('bare smoke: identity seed file is created owner-only and reloads', async (t) => {
  const storage = tmpStorage()
  const relay = new BareRelay({ storage })
  t.teardown(async () => {
    try { await relay.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })

  const first = await relay._deriveKeypair()
  const mode = (await stat(join(storage, 'identity.key'))).mode & 0o777
  const second = await relay._deriveKeypair()

  t.is(mode, 0o600, 'Bare identity seed is owner-read/write only')
  t.alike(second.publicKey, first.publicKey, 'public key reloads from disk')
  t.alike(second.secretKey, first.secretKey, 'secret key reloads from disk')
})

test('bare smoke: identity temp path avoids Node-only process globals', async (t) => {
  const source = await readFile(new URL('../../packages/core/core/relay-node/bare-relay.js', import.meta.url), 'utf8')
  t.ok(source.includes('function identityTempPath (keyPath)'), 'uses a portable temp-path helper')
  t.absent(source.includes('process.pid'), 'Bare identity path does not depend on Node process.pid')
})

test('bare smoke: accept-mode resolver gives same answer as RelayNode for same config', async (t) => {
  // Symmetry check — if these ever diverge, the two runtimes silently apply
  // different policies for identical config. That would be a security bug.
  const bare = new BareRelay({ storage: '/tmp/bare-symm-' + Date.now() })
  const { RelayNode } = await import('p2p-hiverelay/core/relay-node/index.js')
  const node = new RelayNode({ storage: '/tmp/node-symm-' + Date.now() })

  const cases = [
    { acceptMode: 'open', expect: 'open' },
    { acceptMode: 'review', expect: 'review' },
    { acceptMode: 'allowlist', expect: 'allowlist' },
    { acceptMode: 'closed', expect: 'closed' },
    { registryAutoAccept: true, expect: 'open' },
    { registryAutoAccept: false, expect: 'review' }
  ]

  for (const { expect, ...cfg } of cases) {
    Object.assign(bare.config, cfg)
    Object.assign(node.config, cfg)
    delete bare.config.acceptMode
    delete node.config.acceptMode
    Object.assign(bare.config, cfg)
    Object.assign(node.config, cfg)

    const bareMode = bare._resolveAcceptMode()
    const nodeMode = node._resolveAcceptMode()
    t.is(bareMode, nodeMode, `runtimes agree for config ${JSON.stringify(cfg)}`)
    t.is(bareMode, expect, `result is ${expect} as expected`)
  }
})

test('bare smoke: appCatalogPaged is a strict plain object with finite hard bounds', async (t) => {
  for (const value of ['enabled', [], new Date(), 1]) {
    await t.exception.all(
      () => new BareRelay({ storage: tmpStorage(), appCatalogPaged: value }),
      /appCatalogPaged must be a plain object/
    )
  }
  await t.exception.all(
    () => new BareRelay({ storage: tmpStorage(), appCatalogPaged: { actionLimit: 11 } }),
    /safe integer/
  )
  const section = Object.create(null)
  section.digestBudget = 7
  const relay = new BareRelay({ storage: tmpStorage(), appCatalogPaged: section })
  t.is(relay.config.appCatalogPaged.digestBudget, 7)
  t.is(relay.config.appCatalogPaged.actionLimit, 10)
})

test('bare smoke: Core-only ingress binds paged and legacy channels to exact Noise key', (t) => {
  const relay = new BareRelay({ storage: tmpStorage(), enableServices: false })
  const noiseKey = randomBytes(32)
  const misleadingInfoKey = randomBytes(32)
  const noiseHex = noiseKey.toString('hex')
  const attached = []
  relay.appCatalogController = {
    stopped: false,
    attach (_conn, key) { attached.push(['paged', Buffer.from(key).toString('hex')]) },
    scheduleLegacyFallback () { return true },
    cancelLegacyFallback () {},
    legacyEnvelope () { return { envelope: {}, reason: null } }
  }
  const protocol = relay._startCoreServiceProtocol()
  t.is(relay.serviceRegistry.services.size, 0, 'Core-only Bare registry remains empty')
  protocol.attach = (_conn, key) => { attached.push(['legacy', key]) }
  relay.store = { replicate () {} }
  let immediate = null
  relay.swarm = {
    on (name, listener) {
      if (name === 'connection') immediate = listener
    }
  }
  relay._openStorageIngress()
  t.is(typeof immediate, 'function', 'connection listener opens only after both catalog protocols exist')
  const conn = new EventEmitter()
  conn.remotePublicKey = noiseKey
  conn.destroy = () => {}
  immediate(conn, { publicKey: misleadingInfoKey })
  t.alike(attached, [['paged', noiseHex], ['legacy', noiseHex]], 'legacy schedule key equals authenticated Noise key')
})

test('bare smoke: a paged catalog attach fault cannot suppress independent protocols', (t) => {
  const relay = new BareRelay({ storage: tmpStorage() })
  const noiseKey = randomBytes(32)
  const noiseHex = noiseKey.toString('hex')
  const attached = []
  relay._storageIngressReady = true
  relay.appCatalogController = {
    attach () {
      attached.push('catalog')
      throw new Error('injected catalog attach failure')
    }
  }
  relay._seedProtocol = { attach () { attached.push('seed') } }
  relay._circuitRelay = { attach () { attached.push('circuit') } }
  relay._proofOfRelay = { attach () { attached.push('proof') } }
  relay._serviceProtocol = {
    attach (_conn, remote) {
      attached.push(`service:${remote}`)
    }
  }
  relay.store = {
    replicate () { attached.push('replicate') }
  }
  const conn = new EventEmitter()
  conn.remotePublicKey = noiseKey
  conn.destroy = () => {}

  relay._onConnection(conn, { publicKey: randomBytes(32) })

  t.alike(attached, [
    'catalog',
    'seed',
    'circuit',
    'proof',
    `service:${noiseHex}`,
    'replicate'
  ], 'every independent ingress attaches after the catalog fault')
})

test('bare smoke: legacy type-7 receiver is authenticated, bounded, and shutdown fenced', (t) => {
  const relay = new BareRelay({ storage: tmpStorage(), enableSeeding: true, catalogSync: true })
  const accepted = []
  relay._storageIngressReady = true
  relay._applyCatalogActions = input => {
    accepted.push(input)
    return Promise.resolve({ acted: input.apps.length, stop: false })
  }
  const protocol = relay._startCoreServiceProtocol()
  t.is(protocol.listenerCount('app-catalog'), 1, 'Core-only Bare installs the legacy receiver before ingress')
  const remote = catalogKeyPair()
  const app = { appKey: 'a'.repeat(64), maxStorageBytes: 1 }

  protocol.emit('app-catalog', signedLegacyCatalog([app], remote))
  t.is(accepted.length, 1, 'a valid Noise-bound signed catalog reaches the shared action path')
  t.alike(accepted[0], { apps: [app], maxActions: 10 })

  protocol.emit('app-catalog', signedLegacyCatalog([app], remote))
  t.is(accepted.length, 1, 'a second valid type-7 on the same channel cannot repeat actions')
  protocol.emit('channel-close', { remotePubkey: b4a.toString(remote.publicKey, 'hex') })
  t.is(relay._legacyCatalogAcceptedPeers.size, 0, 'exact channel close releases the replay token')

  protocol.emit('app-catalog', signedLegacyCatalog([], remote))
  t.is(accepted.length, 2, 'the exact signed-empty fallback is accepted as complete')
  t.alike(accepted[1].apps, [])

  const invalid = signedLegacyCatalog([app], remote)
  invalid.signature = '0'.repeat(128)
  t.is(relay._handleLegacyAppCatalog(invalid), false, 'a forged signature is rejected')

  const stale = signedLegacyCatalog([app], remote, Date.now() - (6 * 60 * 1000))
  t.is(relay._handleLegacyAppCatalog(stale), false, 'a stale signed catalog is rejected')

  const overEntries = signedLegacyCatalog(Array.from({ length: 129 }, () => app), remote)
  t.is(relay._handleLegacyAppCatalog(overEntries), false, '129 entries exceed the exact legacy cap')
  const overBytes = signedLegacyCatalog([{ ...app, description: 'x'.repeat(66_000) }], remote)
  t.is(relay._handleLegacyAppCatalog(overBytes), false, 'a signed envelope above 65,536 bytes is rejected')
  t.is(relay._handleLegacyAppCatalog(signedLegacyCatalog([app], remote, Date.now(), { delta: true })), false,
    'delta compatibility cannot masquerade as one complete fallback')

  relay._stopRequested = true
  relay._storageIngressReady = false
  relay._legacyCatalogAcceptedPeers.clear()
  protocol.emit('app-catalog', signedLegacyCatalog([app], remote))
  t.is(accepted.length, 2, 'shutdown admits no signature work or catalog action')
})

test('bare smoke: shutdown fence rejects queued paged actions and legacy fallback scheduling', async (t) => {
  const relay = new BareRelay({ storage: tmpStorage(), enableSeeding: true })
  let scheduled = 0
  relay.appCatalogController = {
    stopped: false,
    scheduleLegacyFallback () { scheduled++; return true },
    cancelLegacyFallback () {},
    legacyEnvelope () { return { envelope: {}, reason: null } }
  }
  relay.appRegistry = {
    get () { throw new Error('post-fence registry lookup') }
  }
  relay._stopRequested = true
  relay._storageIngressReady = false

  t.is(relay._scheduleLegacyAppCatalog({ remotePubkey: 'a'.repeat(64), send () {} }), null)
  t.is(scheduled, 0, 'post-fence legacy scheduling never reaches the controller')
  t.alike(await relay._applyPagedCatalogAction({
    remainingActions: 10,
    entries: [{ appKey: 'b'.repeat(64), maxStorageBytes: 1 }]
  }), { acted: 0, stop: true })
})

test('bare smoke: an untrusted peer cannot induce repair work for an existing app', async (t) => {
  const relay = new BareRelay({ storage: tmpStorage(), enableSeeding: true, acceptMode: 'closed' })
  let repairs = 0
  relay._storageIngressReady = true
  relay._stopRequested = false
  relay.appRegistry = { get () { return { anchored: false } } }
  relay.appLifecycle = {
    async repairUnanchored () { repairs++ }
  }

  const result = await relay._applyPagedCatalogAction({
    peerPubkey: 'a'.repeat(64),
    remainingActions: 10,
    entries: [createCanonicalCatalogRow({
      appKey: 'b'.repeat(64),
      appId: null,
      type: 'app',
      parentKey: null,
      mountPath: null,
      version: null,
      discoveryKey: null,
      blind: false,
      storageClass: 'persistent',
      availabilityClass: 'always-on',
      privacyTier: 'public',
      seededAt: null,
      redacted: false,
      metadataVisibility: 'public',
      blindContentId: null,
      anchored: true,
      maxStorageBytes: 1,
      publisherPubkey: null,
      durability: 0,
      revocable: true,
      retainUntil: null
    })]
  })

  t.alike(result, { acted: 0, stop: false })
  t.is(repairs, 0, 'closed-mode authenticated peer schedules no repair/network work')
})

test('bare smoke: federation module is wired (instance exists pre-start)', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-fed-' + Date.now() })
  // Federation is constructed inside start() in BareRelay, not in the
  // constructor — verify the property exists and starts null.
  t.is(relay.federation, null, 'federation slot exists, lazily constructed in start()')
})

test('bare lifecycle destroys every protocol owner and retains rejected teardown for retry', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-protocol-' + Date.now() })
  const events = []
  let rejectProof = true
  relay._serviceProtocol = { destroy () { events.push('service') } }
  relay._seedProtocol = { destroy () { events.push('seed') } }
  relay._circuitRelay = { destroy () { events.push('circuit') } }
  const proof = {
    destroy () {
      events.push('proof')
      if (rejectProof) throw new Error('injected proof destroy failure')
    }
  }
  relay._proofOfRelay = proof

  await t.exception(relay._destroyProtocolHandlers(100), /injected proof destroy failure/)
  t.alike(events, ['service', 'seed', 'circuit', 'proof'])
  t.is(relay._serviceProtocol, null)
  t.is(relay._seedProtocol, null)
  t.is(relay._circuitRelay, null)
  t.is(relay._proofOfRelay, proof, 'rejected owner remains reachable')

  rejectProof = false
  await relay._destroyProtocolHandlers(100)
  t.is(relay._proofOfRelay, null)
})

test('bare lifecycle drains scope then tears down every seeded drive before store ownership', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-drive-' + Date.now() })
  const events = []
  relay._scope = { async drain () { events.push('scope-drained') } }
  relay.appRegistry = boundedAppRegistry(new Map([['a'.repeat(64), {}], ['b'.repeat(64), {}]]))
  relay.appLifecycle = {
    async unseedApp (key, opts) {
      events.push('unseed-' + key[0] + '-' + String(opts.forget))
    }
  }

  await relay._drainLifecycleAndSeededDrives(100)
  t.alike(events, ['scope-drained', 'unseed-a-false', 'unseed-b-false'])
  t.is(relay._scope, null)
})

test('bare lifecycle retirement consumes only finite registry pages', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-drive-pages-' + Date.now() })
  const apps = new Map()
  for (let i = 0; i < 130; i++) apps.set(i.toString(16).padStart(64, '0'), {})
  const registry = boundedAppRegistry(apps)
  const page = registry.page.bind(registry)
  let pageCalls = 0
  let largestPage = 0
  let largestBudget = 0
  registry.page = (consumer, budget) => {
    const result = page(consumer, budget)
    pageCalls++
    largestPage = Math.max(largestPage, result.entries.length)
    largestBudget = Math.max(largestBudget, budget)
    return result
  }
  relay.appRegistry = registry
  let unseeded = 0
  let allForgetFalse = true
  relay.appLifecycle = {
    async unseedApp (_key, opts) {
      if (opts.forget !== false) allForgetFalse = false
      unseeded++
    }
  }

  await relay._drainLifecycleAndSeededDrives(1_000)
  t.ok(allForgetFalse, 'every bounded retirement preserves the durable row')
  t.is(unseeded, 130, 'each drive identity is retired exactly once')
  t.is(largestBudget, 64, 'the caller never widens the hard page budget')
  t.is(largestPage, 64, 'no page materializes more than the hard bound')
  t.ok(pageCalls >= 6, 'retirement and stable verification both advance bounded pages')
})

test('bare lifecycle retirement fails closed without bounded registry ownership', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-drive-page-required-' + Date.now() })
  relay.appRegistry = { apps: new Map() }
  relay.appLifecycle = { async unseedApp () {} }
  let observed = null
  try { await relay._drainLifecycleAndSeededDrives(100) } catch (err) { observed = err }
  t.is(observed?.code, 'APP_REGISTRY_BOUNDED_PAGE_REQUIRED')
})

test('bare lifecycle fences a shared-flight owner before terminal close and suppresses new work', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-owner-fence-' + Date.now() })
  const events = []
  const protocol = {
    destroy () { events.push('terminal-close') }
  }
  relay._seedProtocol = protocol
  relay._scope = { abort () { events.push('scope-fence') } }
  relay.appLifecycle = {
    beginShutdown () { events.push('app-fence') }
  }

  const raw = sharedOperationFlights.run(
    protocol,
    'bare.test.never-settles',
    () => new Promise(() => {}),
    { owner: protocol, timeoutMs: 1_000 }
  )
  raw.catch(() => {})
  await Promise.resolve()

  const fence = relay._installBareShutdownFence('test')
  const fencedStats = sharedOperationFlights.getStats(protocol).owner
  t.alike(events, ['scope-fence', 'app-fence'], 'global and AppLifecycle fences run synchronously before close')
  t.is(fencedStats.accepting, false, 'owner rejects new shared work at the atomic fence')
  t.is(fencedStats.activeFlights, 1, 'pre-fence raw flight remains explicitly owned')

  let startedLate = false
  await t.exception(sharedOperationFlights.run(
    protocol,
    'bare.test.late',
    async () => { startedLate = true },
    { owner: protocol, timeoutMs: 100 }
  ), /owner is not accepting new work/)
  t.is(startedLate, false, 'post-fence raw operation never starts')

  const generation = relay._bareRuntimeOwners.get(protocol).generation
  await relay._retireBareRuntimeOwner(protocol, 'seedProtocol', () => protocol.destroy(), 1)
  t.alike(events, ['scope-fence', 'app-fence', 'terminal-close'], 'never-settling flight reaches terminal close only after the drain attempt')
  t.is(sharedOperationFlights.getStats(protocol).owner.activeFlights, 0, 'terminal close releases the exact orphaned flight')
  t.is(fence.generation, 1, 'one global shutdown generation was installed')
  t.is(generation, fencedStats.generation, 'retirement retains the invalidated owner generation')
})

test('bare lifecycle invalidates owners before hooks and retries a failed exact hook', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-hook-retry-' + Date.now() })
  const protocol = { destroy () {} }
  let attempts = 0
  let reentrantStarted = false
  const reentrantResults = []
  relay._seedProtocol = protocol
  relay.appLifecycle = {
    beginShutdown () {
      attempts++
      reentrantResults.push(sharedOperationFlights.run(
        protocol,
        `bare.test.reentrant.${attempts}`,
        async () => { reentrantStarted = true },
        { owner: protocol, timeoutMs: 100 }
      ).catch(err => err))
      if (attempts === 1) throw new Error('injected beginShutdown failure')
    }
  }

  const first = relay._installBareShutdownFence('test-hook-retry')
  const generation = relay._bareRuntimeOwners.get(protocol).generation
  t.is(first.firstError?.message, 'injected beginShutdown failure')
  t.is(sharedOperationFlights.getStats(protocol).owner.accepting, false, 'owner was invalidated before hook re-entry')

  const second = relay._installBareShutdownFence('test-hook-retry')
  const results = await Promise.all(reentrantResults)
  t.is(second, first, 'retry retains the exact global fence')
  t.is(attempts, 2, 'only the unresolved hook is retried')
  t.is(second.firstError, null, 'successful retry clears transient hook poison')
  t.is(relay._bareRuntimeOwners.get(protocol).generation, generation, 'hook retry keeps the same owner generation')
  t.is(reentrantStarted, false, 'neither re-entrant shared operation starts')
  t.ok(results.every(err => err?.code === 'SHARED_FLIGHT_OWNER_INVALIDATED'))
})

test('bare lifecycle shares one unresolved terminal call across concurrent retirement waves', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-terminal-raw-' + Date.now() })
  const gate = deferred()
  const owner = {}
  let terminalCalls = 0
  const terminal = async () => {
    terminalCalls++
    await gate.promise
  }

  const first = relay._retireBareRuntimeOwner(owner, 'testOwner', terminal, 30_000)
  await Promise.resolve()
  await Promise.resolve()
  const concurrent = relay._retireBareRuntimeOwner(owner, 'testOwner', terminal, 30_000)
  await Promise.resolve()
  t.is(terminalCalls, 1, 'concurrent retry retains the exact unresolved terminal call')

  gate.resolve()
  await Promise.all([first, concurrent])
  t.is(terminalCalls, 1, 'terminal close is never duplicated after true settlement')
  t.is(sharedOperationFlights.getStats(owner).owner.activeFlights, 0)
})

test('bare lifecycle drains the full service chain before protocol close and provider stop', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-service-order-' + Date.now() })
  const events = []
  let protocolDrains = 0
  let registryDrains = 0
  relay._serviceProtocol = {
    beginShutdown () { events.push('protocol-fence') },
    async drainRequests () { events.push(`protocol-drain-${++protocolDrains}`) },
    destroy () { events.push('protocol-close') }
  }
  relay.serviceRegistry = {
    services: new Map(),
    beginShutdown () { events.push('registry-fence') },
    async drainRequests () { events.push(`registry-drain-${++registryDrains}`) },
    async stopAll () { events.push('providers-stop') }
  }

  relay._installBareShutdownFence('test-service-order')
  await relay._stopBareServiceIngress(1_000)
  await relay._stopBareServices(1_000)

  t.alike(events, [
    'protocol-fence',
    'registry-fence',
    'protocol-drain-1',
    'registry-drain-1',
    'protocol-close',
    'protocol-drain-2',
    'registry-drain-2',
    'registry-drain-3',
    'providers-stop',
    'registry-drain-4'
  ])
})

test('bare lifecycle bounded waves fail closed until a stable empty drive wave', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-drive-waves-' + Date.now() })
  const appKey = 'c'.repeat(64)
  let entry = {}
  let replaceEntry = true
  let unseedCalls = 0
  relay.appRegistry = boundedAppRegistry(new Map([[appKey, entry]]))
  relay.appLifecycle = {
    beginShutdown () {},
    async drainRetiringDrives () {},
    async unseedApp (key, opts) {
      t.is(opts.forget, false, 'every wave preserves the durable row')
      unseedCalls++
      if (replaceEntry) {
        entry = {}
        relay.appRegistry.apps.set(key, entry)
      }
    }
  }

  let pending = null
  try { await relay._drainLifecycleAndSeededDrives(1_000) } catch (err) { pending = err }
  t.is(pending?.code, 'BARE_OWNER_RETIREMENT_PENDING', 'bounded churn cannot be declared quiescent')
  t.ok(unseedCalls > 1, 'multiple exposed retirement waves were attempted')
  t.ok(relay.appRegistry.apps.has(appKey), 'durable row remains present after the failed wave')

  replaceEntry = false
  await relay._drainLifecycleAndSeededDrives(1_000)
  t.ok(relay.appRegistry.apps.has(appKey), 'a later stable wave settles without forgetting the row')
})

test('bare lifecycle normal stop retains a failed exact owner and retries without reopening ingress', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-stop-retry-' + Date.now(), shutdownTimeoutMs: 20 })
  const appKey = 'a'.repeat(64)
  const entry = { drive: {} }
  const events = []
  let closeAttempts = 0

  relay.running = true
  relay._storageIngressReady = true
  relay.appLifecycle = {
    beginShutdown () { events.push('fence') },
    async drainRetiringDrives () { events.push('retiring-drain') },
    async unseedApp (key, opts) {
      events.push(`unseed-${key[0]}-${String(opts.forget)}`)
      entry.drive = null
    }
  }
  relay.appRegistry = boundedAppRegistry(new Map([[appKey, entry]]), {
    async flush () { events.push('registry-flush') },
    detachStore () { events.push('registry-detach') }
  })
  relay.storageAdmission = {
    closeMutations () { events.push('mutations-fenced') },
    async drainMutations () { events.push('mutations-drained') },
    failClosed () { events.push('admission-fail-closed') }
  }
  const store = {
    async close () {
      closeAttempts++
      events.push('store-close-' + closeAttempts)
      if (closeAttempts === 1) throw new Error('injected Bare root close failure')
    }
  }
  relay.store = store

  await t.exception(relay.stop(), /injected Bare root close failure/)
  const retained = relay._bareRuntimeOwners.get(store)
  t.ok(retained, 'failed terminal owner remains strongly reachable')
  t.is(retained.state, 'FENCED', 'failed owner remains fenced')
  const retainedGeneration = retained.generation
  t.is(relay._shutdownFence.state, 'FENCED', 'global fence remains closed after failure')
  t.ok(relay.appRegistry.apps.has(appKey), 'shutdown preservation keeps the durable registry row')
  t.is(entry.drive, null, 'live drive reference was quiesced')

  let rejected = null
  try { relay.unseedApp(appKey) } catch (err) { rejected = err }
  t.is(rejected?.code, 'SHUTTING_DOWN', 'post-fence operator forget is rejected')

  await relay.stop()
  t.is(relay.running, false, 'retry completes shutdown')
  t.is(relay.store, null, 'exact root owner is released after successful retry')
  t.is(relay._shutdownFence.state, 'COMPLETE', 'fence records complete settlement')
  t.is(closeAttempts, 2, 'terminal close is retried only after its rejected attempt')
  t.is(retained.generation, retainedGeneration, 'retry preserves the exact owner generation')
  t.is(events.filter(event => event === 'fence').length, 1, 'global AppLifecycle fence is installed once')
  t.is(events.filter(event => event === 'unseed-a-false').length, 1, 'settled shutdown drive is not closed twice across retry waves')
})

test('bare lifecycle startup rollback uses the same retained owner generation', async (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-rollback-retry-' + Date.now(), shutdownTimeoutMs: 20 })
  let closes = 0
  const store = {
    async close () {
      closes++
      if (closes === 1) throw new Error('injected rollback close failure')
    }
  }
  relay.store = store
  relay.appLifecycle = {
    beginShutdown () {},
    async drainRetiringDrives () {}
  }
  relay.appRegistry = boundedAppRegistry(new Map(), {
    async flush () {},
    detachStore () {}
  })
  relay.storageAdmission = {
    closeMutations () {},
    async drainMutations () {},
    failClosed () {}
  }

  await t.exception(relay._rollbackFailedStart(), /corestore teardown did not settle/)
  const retained = relay._bareRuntimeOwners.get(store)
  const generation = retained.generation
  t.is(relay._shutdownFence.reason, 'startup-rollback')
  t.is(retained.state, 'FENCED')

  await relay._rollbackFailedStart()
  t.is(closes, 2, 'rollback retry reaches the same terminal owner')
  t.is(retained.generation, generation, 'rollback retry does not roll owner generation')
  t.is(relay._shutdownFence.state, 'COMPLETE')
})
