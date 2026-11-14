import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { mkdtemp, readdir, realpath, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from '../../packages/core/core/app-registry.js'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import {
  APP_CATALOG_LIMITS,
  createAppCatalogAbort,
  createAppCatalogSnapshotIdentity,
  verifyAppCatalogAbort
} from '../../packages/core/core/relay-node/app-catalog-paged.js'
import { AppCatalogController } from '../../packages/core/core/relay-node/app-catalog-controller.js'
import { AppCatalogDiskStageFactory } from '../../packages/core/core/relay-node/app-catalog-paged-stage.js'
import {
  appRegistryCatalogSource,
  assertAppRegistryCatalogIngress
} from '../../packages/core/core/relay-node/app-catalog-source.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

class EmptyRegistry extends EventEmitter {
  page () {
    return { entries: [], examined: 0, complete: true }
  }

  releasePopulationConsumer () {}
  setCatalogIngressValidator () {}
}

function controller (opts = {}) {
  return new AppCatalogController({
    appRegistry: new EmptyRegistry(),
    keyPair: keyPair(),
    stageFactory: {
      async ready () {},
      async stop () {}
    },
    ...opts
  })
}

function deferred () {
  let resolve
  const promise = new Promise(_resolve => { resolve = _resolve })
  return { promise, resolve }
}

function peer (number) {
  return number.toString(16).padStart(64, '0')
}

function completed (peerPubkey, catalog) {
  return {
    snapshot: {
      senderPubkey: peerPubkey,
      snapshotId: peerPubkey,
      highWater: 1,
      rootDigest: peerPubkey,
      entryCount: 0
    },
    catalog
  }
}

function retainedCatalog (opts = {}) {
  const state = { refs: 0, reads: 0, releases: 0 }
  const create = () => {
    let released = false
    state.refs++
    return {
      acquire () {
        if (released) throw new Error('catalog handle is released')
        return create()
      },
      async readPage (request) {
        if (released) throw new Error('catalog handle is released')
        state.reads++
        if (opts.readPage) return opts.readPage(request)
        return { entries: [], cursor: null, complete: true }
      },
      release () {
        if (released) return Promise.resolve(false)
        released = true
        state.refs--
        state.releases++
        try {
          const result = opts.release ? opts.release({ ...state }) : true
          return Promise.resolve(result === undefined ? true : result)
        } catch (err) {
          return Promise.reject(err)
        }
      }
    }
  }
  return { catalog: create(), state }
}

function fakeClock () {
  let now = 0
  let nextId = 1
  const timers = new Map()
  return {
    setTimeout (fn, delay) {
      const timer = { id: nextId++, at: now + delay, fn, unref () {} }
      timers.set(timer.id, timer)
      return timer
    },
    clearTimeout (timer) {
      timers.delete(timer.id)
    },
    tick (elapsed) {
      now += elapsed
      const due = [...timers.values()].filter(timer => timer.at <= now).sort((a, b) => a.at - b.at)
      for (const timer of due) {
        if (!timers.delete(timer.id)) continue
        timer.fn()
      }
    }
  }
}

async function emptyCommittedCatalog (factory, senderPubkey, highWater) {
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey, highWater, rows: [] })
  const stage = await factory.open({
    peerPubkey: senderPubkey,
    snapshotId: snapshot.snapshotId,
    highWater: snapshot.highWater,
    rootDigest: snapshot.rootDigest,
    entryCount: snapshot.entryCount
  })
  return {
    snapshot: Object.freeze({ ...snapshot, senderPubkey }),
    catalog: await stage.commit(snapshot)
  }
}

test('catalog source projects public and redacted entries without synthesizing identity', (t) => {
  const appKey = 'a'.repeat(64)
  const publicSource = appRegistryCatalogSource(appKey, {
    type: 'app',
    appId: 'example',
    version: '1.2.3',
    maxStorage: 1024,
    privacyTier: 'public'
  })
  t.is(publicSource.record.appKey, appKey)
  t.is(publicSource.record.appId, 'example')
  t.is(publicSource.record.maxStorageBytes, 1024)

  const redacted = appRegistryCatalogSource(appKey, {
    type: 'app',
    appId: 'secret',
    blind: true,
    blindContentId: 'b'.repeat(64),
    maxStorage: 0
  })
  t.is(redacted.record.appKey, null, 'redacted identity is not synthesized from blindContentId')
  t.is(redacted.record.appId, null)
  t.is(redacted.record.blindContentId, 'b'.repeat(64))
  t.is(redacted.record.maxStorageBytes, null, 'zero is not a positive storage commitment')

  const unknownTier = appRegistryCatalogSource(appKey, {
    type: 'app',
    appId: 'must-not-leak',
    privacyTier: 'secret'
  })
  t.is(unknownTier.record.redacted, true, 'unknown raw privacy tier fails closed')
  t.is(unknownTier.record.appKey, null)
  t.is(unknownTier.record.appId, null)
})

test('AppRegistry catalog ingress rejects before membership or generation mutation', (t) => {
  const registry = new AppRegistry(null)
  const appKey = 'c'.repeat(64)
  registry.set(appKey, { type: 'app', appId: 'valid', version: '1.0.0' }, { persist: false })
  registry.setCatalogIngressValidator((key, entry) => {
    if (entry.version === 'invalid') throw new Error(`invalid catalog row ${key}`)
  })
  const before = structuredClone(registry.get(appKey))

  t.exception(
    () => registry.update(appKey, { version: 'invalid' }, { persist: false }),
    /invalid catalog row/
  )
  t.alike(registry.get(appKey), before, 'failed update leaves the live entry and generation unchanged')

  const newKey = 'd'.repeat(64)
  t.exception(
    () => registry.set(newKey, { type: 'app', appId: 'new', version: 'invalid' }, { persist: false }),
    /invalid catalog row/
  )
  t.absent(registry.has(newKey), 'failed set creates no membership')
})

test('custody linkage backfill cannot mutate registry or MVCC before ingress validation', (t) => {
  const registry = new AppRegistry(null)
  const appKey = 'f'.repeat(64)
  registry.set(appKey, {
    type: 'drive',
    blind: true,
    privacyTier: 'p2p-only',
    maxStorage: 1024
  }, { persist: false })
  registry.setCatalogIngressValidator(assertAppRegistryCatalogIngress)

  const c = controller({ appRegistry: registry })
  c._advanceSource()
  const before = structuredClone(registry.get(appKey))
  const revision = c.store.lastCatalogRevision
  const events = []
  const node = Object.create(RelayNode.prototype)
  node.appRegistry = registry
  node.seedingRegistry = {
    getCustodyIntent () {
      return { blindContentId: 'not-hex', retainUntil: -1 }
    }
  }
  node.emit = (name, value) => events.push({ name, value })

  t.is(node._backfillCustodyLinkage(appKey, registry.get(appKey), 'intent-1'), false)
  t.alike(registry.get(appKey), before, 'invalid detached update leaves live registry unchanged')
  t.is(c.store.lastCatalogRevision, revision, 'failed ingress emits no change and advances no MVCC revision')
  t.is(events.length, 1)
  t.is(events[0].name, 'custody-linkage-error')
})

test('action replacement cannot let an old in-flight completion delete the new snapshot', async (t) => {
  const callback = deferred()
  const oldRead = deferred()
  let callbackCalls = 0
  const c = controller({
    onCatalogActionPage: async () => {
      callbackCalls++
      return callback.promise
    }
  })
  c._actionScheduler = { trigger () {} }
  const remote = peer(1)
  const oldCatalog = retainedCatalog({ readPage: () => oldRead.promise })
  const newCatalog = retainedCatalog()

  c._catalogCommitted(completed(remote, oldCatalog.catalog))
  await oldCatalog.catalog.release()
  const flight = c._advanceAction()
  await Promise.resolve()
  c._catalogCommitted(completed(remote, newCatalog.catalog))
  await newCatalog.catalog.release()
  t.not(c._actionQueue.get(remote).catalog, newCatalog.catalog, 'new generation owns a distinct acquired handle')
  t.is(oldCatalog.state.refs, 1, 'old committed handle remains retained while read is in flight')
  oldRead.resolve({ entries: [], cursor: null, complete: true })
  callback.resolve({ acted: 0 })
  await flight
  t.is(callbackCalls, 0, 'superseded disk read cannot invoke the stale action callback')
  t.is(c._actionQueue.get(remote).snapshot.senderPubkey, remote, 'old completion conditionally preserves the replacement')
  await c._drainCatalogReleases()
  t.is(oldCatalog.state.refs, 0, 'superseded handle releases after its exact flight settles')
  t.is(newCatalog.state.refs, 1, 'replacement remains acquired for its pending action')
})

test('stop during an action disk read fences callback and retires the exact handle', async (t) => {
  const read = deferred()
  let callbackCalls = 0
  const c = controller({
    onCatalogActionPage: async () => {
      callbackCalls++
      return { acted: 1 }
    }
  })
  c._actionScheduler = { trigger () {} }
  const remote = peer(9)
  const retained = retainedCatalog({ readPage: () => read.promise })
  c._catalogCommitted(completed(remote, retained.catalog))
  await retained.catalog.release()
  const flight = c._advanceAction()
  await Promise.resolve()
  c._stopped = true
  read.resolve({ entries: [], cursor: null, complete: true })
  const result = await flight
  t.is(result.fenced, true)
  t.is(callbackCalls, 0)
  t.is(c._actionQueue.size, 0)
  await c._drainCatalogReleases()
  t.is(retained.state.refs, 0)
})

test('failed stage readiness rejects one shared start flight and retry cannot hang', async (t) => {
  let readyCalls = 0
  const c = controller({
    stageFactory: {
      async ready () {
        readyCalls++
        if (readyCalls === 1) throw new Error('stage unavailable')
      },
      async stop () {}
    }
  })
  const first = c.start()
  const concurrent = c.start()
  t.is(first, concurrent, 'concurrent callers share the exact start flight')
  await t.exception(first, /stage unavailable/)
  t.is(c._started, false)
  const retryFlight = c.start()
  const retry = await retryFlight
  t.is(retry.available, true, 'retry reaches a completed initial snapshot')
  t.is(c.start(), retryFlight, 'successful start retains one exact completion authority')
  await c.stop()
})

test('beginShutdown settles a start blocked in stage readiness without publishing owners', async (t) => {
  const ready = deferred()
  let stopCalls = 0
  const c = controller({
    stageFactory: {
      ready: () => ready.promise,
      async stop () { stopCalls++ }
    }
  })
  const flight = c.start()
  await Promise.resolve()
  c.beginShutdown()

  t.alike(await flight, { available: false, stopped: true })
  t.is(c._started, false)
  t.is(c.outbound, null, 'no manager is constructed after the startup fence')
  t.is(c._sourceScheduler, null, 'no scheduler is constructed after the startup fence')

  ready.resolve()
  await Promise.resolve()
  await c.stop()
  t.is(stopCalls, 1)
})

test('beginShutdown settles a start waiting for its first source snapshot and fences schedulers', async (t) => {
  class PendingRegistry extends EmptyRegistry {
    page () { return { entries: [], examined: 0, complete: false } }
  }
  const c = controller({ appRegistry: new PendingRegistry() })
  const flight = c.start()
  while (!c._started) await Promise.resolve()
  c.beginShutdown()

  t.alike(await flight, { available: false, stopped: true })
  t.is(c.store.publishedSnapshot, null)
  t.ok(c._sourceScheduler.snapshot().stopping, 'source scheduler rejects post-fence work')
  t.ok(c._digestScheduler.snapshot().stopping, 'digest scheduler rejects post-fence work')
  t.ok(c._inboundSweepScheduler.snapshot().stopping, 'inbound scheduler rejects post-fence work')
  t.ok(c._actionScheduler.snapshot().stopping, 'action scheduler rejects post-fence work')
  await c.stop()
})

test('concurrent controller stop callers share the exact terminal drain', async (t) => {
  const drain = deferred()
  const c = controller()
  c._sourceScheduler = { stop: () => drain.promise }

  const first = c.stop()
  const second = c.stop()
  let secondSettled = false
  second.then(() => { secondSettled = true })
  await Promise.resolve()

  t.is(second, first, 'every caller receives one exact stop authority')
  t.is(secondSettled, false, 'the second caller cannot bypass the active drain')
  drain.resolve()
  await first
  t.is(secondSettled, true, 'all callers settle after terminal teardown')
})

test('a rejected controller stop retains the fence and retries only unresolved teardown', async (t) => {
  let stageStops = 0
  let storeStops = 0
  let sourceStops = 0
  let releaseDrains = 0
  const c = controller({
    stageFactory: {
      async ready () {},
      async stop () {
        stageStops++
        if (stageStops === 1) throw new Error('injected stage cleanup failure')
      }
    }
  })
  c._sourceScheduler = { async stop () { sourceStops++ } }
  c._drainCatalogReleases = async () => { releaseDrains++ }
  c.store.stop = () => { storeStops++ }

  const rejected = c.stop()
  await t.exception(rejected, /stage cleanup failure/)
  t.is(c._shutdownRequested, true, 'a failed attempt cannot reopen catalog work')
  t.is(c._stopFlight, null, 'only the rejected terminal authority is released for retry')
  t.is(storeStops, 1, 'downstream store teardown still runs after a stage fault')
  const sourceStopsAfterFirstAttempt = sourceStops

  const retry = c.stop()
  t.not(retry, rejected, 'retry owns a fresh terminal authority')
  await retry
  t.is(stageStops, 2, 'the unresolved stage cleanup is retried')
  t.is(sourceStops, sourceStopsAfterFirstAttempt, 'an already-settled scheduler is not stopped again on retry')
  t.is(releaseDrains, 1, 'an already-settled release phase is not repeated')
  t.is(storeStops, 1, 'an already-settled downstream store is not stopped twice')
  t.is(c.stop(), retry, 'successful stop remains exactly idempotent')
})

test('controller stop retains manager failures and retries only unresolved owners', async (t) => {
  let outboundStops = 0
  let inboundStops = 0
  let stageStops = 0
  let storeStops = 0
  const c = controller({
    stageFactory: {
      async ready () {},
      async stop () { stageStops++ }
    }
  })
  c.outbound = {
    async stop () {
      outboundStops++
      if (outboundStops === 1) throw new Error('injected outbound drain failure')
    }
  }
  c.inbound = {
    async stop () {
      inboundStops++
      if (inboundStops === 1) throw new Error('injected inbound drain failure')
    }
  }
  c.store.stop = () => { storeStops++ }

  await t.exception(c.stop(), /injected outbound drain failure/)
  t.is(outboundStops, 1)
  t.is(inboundStops, 1, 'inbound receives a best-effort attempt after outbound rejection')
  t.is(stageStops, 1, 'downstream stage cleanup is still attempted')
  t.is(storeStops, 1, 'downstream store cleanup is still attempted')

  await c.stop()
  t.is(outboundStops, 2, 'failed outbound manager is retried')
  t.is(inboundStops, 2, 'failed inbound manager is retried')
  t.is(stageStops, 1, 'settled stage cleanup is not repeated')
  t.is(storeStops, 1, 'settled store cleanup is not repeated')
})

test('controller stop drains async catalog notifications before stage teardown', async (t) => {
  const notification = deferred()
  let stageStopped = false
  const c = controller({
    stageFactory: {
      async ready () {},
      async stop () { stageStopped = true }
    },
    onCatalogComplete: () => notification.promise
  })
  c._catalogCommitted(completed(peer(11), retainedCatalog().catalog))

  const stopping = c.stop()
  await Promise.resolve()
  await Promise.resolve()
  t.is(stageStopped, false, 'stage ownership remains while notification metadata is in flight')
  notification.resolve()
  await stopping
  t.is(stageStopped, true, 'stage teardown follows notification settlement')
  t.is(c._notificationFlights.size, 0)
})

test('action queue remains at the exact inbound-peer cap under sequential peer churn', async (t) => {
  const catalogs = []
  const c = controller({ onCatalogActionPage: async () => ({ acted: 0 }) })
  c._actionScheduler = { trigger () {} }
  for (let i = 1; i <= APP_CATALOG_LIMITS.maxInboundPeers + 1; i++) {
    const retained = retainedCatalog()
    catalogs.push(retained)
    c._catalogCommitted(completed(peer(i), retained.catalog))
    await retained.catalog.release()
  }
  await c._drainCatalogReleases()
  t.is(c._actionQueue.size, APP_CATALOG_LIMITS.maxInboundPeers)
  t.absent(c._actionQueue.has(peer(1)), 'oldest queued peer is retired')
  t.ok(c._actionQueue.has(peer(APP_CATALOG_LIMITS.maxInboundPeers + 1)), 'newest completed peer is retained')
  t.is(catalogs[0].state.refs, 0, 'evicted catalog handle is released exactly once')
  t.is(catalogs[1].state.refs, 1, 'non-evicted catalog remains retained')
})

test('controller caps negotiating channels before allocating a 257th capability', (t) => {
  const errors = []
  const c = controller({ onError: event => errors.push(event) })
  c._started = true
  c.outbound = {}
  c.inbound = {}
  for (let i = 1; i <= APP_CATALOG_LIMITS.maxInboundPeers; i++) c.channels.set(peer(i), {})
  t.is(c.attach(null, peer(APP_CATALOG_LIMITS.maxInboundPeers + 1)), null)
  t.is(c.channels.size, APP_CATALOG_LIMITS.maxInboundPeers)
  t.is(errors[0].phase, 'attach')
  t.is(errors[0].error.code, 'RESOURCE_LIMIT')
})

test('legacy fallback timeout and not-ready channel close share one terminal decision', async (t) => {
  const clock = fakeClock()
  const sent = []
  const c = controller({
    setTimeout: (fn, ms) => clock.setTimeout(fn, ms),
    clearTimeout: timer => clock.clearTimeout(timer)
  })
  const remote = peer(1)
  const state = { peer: remote, ready: false, closed: false }
  c.channels.set(remote, state)
  c.inbound = { async closePeer () {} }
  c.outbound = { closePeer () {} }
  c.scheduleLegacyFallback(remote, () => { sent.push('timeout') })
  clock.tick(APP_CATALOG_LIMITS.negotiationTimeoutMs - 1)
  t.alike(sent, [])
  clock.tick(1)
  t.alike(sent, ['timeout'])
  await c._channelClosed(state)
  t.alike(sent, ['timeout'], 'channel close after timer cannot duplicate the fallback')

  const early = peer(2)
  const earlyState = { peer: early, ready: false, closed: false }
  c.channels.set(early, earlyState)
  c.scheduleLegacyFallback(early, () => { sent.push('close') })
  await c._channelClosed(earlyState)
  clock.tick(APP_CATALOG_LIMITS.negotiationTimeoutMs)
  t.alike(sent, ['timeout', 'close'], 'not-ready close resolves once before the timer')

  const ready = peer(3)
  c.channels.set(ready, { peer: ready, ready: true, closed: false })
  c.scheduleLegacyFallback(ready, () => { sent.push('ready') })
  c.cancelLegacyFallback(ready)
  clock.tick(APP_CATALOG_LIMITS.negotiationTimeoutMs)
  t.absent(sent.includes('ready'), 'capability completion at the boundary suppresses legacy send')

  const duplicate = peer(4)
  c.scheduleLegacyFallback(duplicate, () => { sent.push('stale') })
  c.scheduleLegacyFallback(duplicate, () => { sent.push('newest') })
  clock.tick(APP_CATALOG_LIMITS.negotiationTimeoutMs)
  t.absent(sent.includes('stale'))
  t.ok(sent.includes('newest'), 'duplicate scheduling retains one newest fallback owner')
})

test('completed catalog action owns a distinct handle after inbound release', async (t) => {
  const observed = []
  const retained = retainedCatalog({
    readPage: () => ({ entries: [['row']], cursor: null, complete: true })
  })
  const c = controller({
    onCatalogComplete: event => { observed.push(event) },
    onCatalogActionPage: async action => {
      t.alike(action.entries, [['row']], 'delayed action can still read after inbound ownership releases')
      return { acted: 0 }
    }
  })
  c._actionScheduler = { trigger () {} }
  const remote = peer(17)
  c._catalogCommitted(completed(remote, retained.catalog))
  await retained.catalog.release()
  t.is(retained.state.refs, 1, 'action-owned acquisition survives original release')
  await c._advanceAction()
  await c._drainCatalogReleases()
  t.is(retained.state.refs, 0)
  await Promise.resolve()
  t.absent(Object.prototype.hasOwnProperty.call(observed[0], 'catalog'), 'notification never exposes the inbound-owned handle')
})

test('rejected acquired-handle release is reported, drained, and never removed early', async (t) => {
  const errors = []
  const removals = []
  const actionHandle = {
    async readPage () { return { entries: [], cursor: null, complete: true } },
    release () { return Promise.reject(new Error('injected release rejection')) }
  }
  const rootHandle = {
    acquire () { return actionHandle },
    release () { return Promise.resolve(true) }
  }
  const c = controller({
    stageFactory: {
      async ready () {},
      async stop () {},
      async removeCommittedPeer (remote) { removals.push(remote) }
    },
    onCatalogActionPage: async () => ({ acted: 0 }),
    onError: event => errors.push(event)
  })
  c._actionScheduler = { trigger () {} }
  c._catalogCommitted(completed(peer(18), rootHandle))
  await c._advanceAction()
  await c._drainCatalogReleases()
  t.ok(errors.some(event => event.phase === 'catalog-release' && /release rejection/.test(event.error.message)))
  t.alike(removals, [], 'failed release never races deletion of a possibly leased snapshot')
})

test('controller status exposes a latched disk-stage cleanup fault', (t) => {
  const c = controller({
    stageFactory: {
      storageFault: true,
      async ready () {},
      async stop () {}
    }
  })
  t.is(c.status().storageFault, true)
})

test('mismatched or forged remote ABORT cannot retire any controller session', async (t) => {
  const relay = keyPair()
  const remote = keyPair()
  const c = controller({ keyPair: relay })
  const remoteHex = b4a.toString(remote.publicKey, 'hex')
  const expectedSnapshot = 'a'.repeat(64)
  c.outbound = {
    acceptAbort (_peer, input) {
      try {
        const verified = verifyAppCatalogAbort(input, {
          localPubkey: b4a.toString(relay.publicKey, 'hex'),
          remotePubkey: remoteHex
        })
        return { status: verified.snapshotId === expectedSnapshot ? 'closed' : 'mismatch' }
      } catch {
        return { status: 'mismatch' }
      }
    }
  }
  c.inbound = { sessions: new Map() }
  const state = { peer: remoteHex }
  const wrongSnapshot = createAppCatalogAbort({
    receiverPubkey: b4a.toString(relay.publicKey, 'hex'),
    snapshotId: 'b'.repeat(64),
    code: 'SNAPSHOT_MISMATCH'
  }, remote)
  await t.exception(c._receiveAbort(state, wrongSnapshot), /exact verified catalog session/)
  await t.exception(c._receiveAbort(state, { ...wrongSnapshot, signature: '0'.repeat(128) }), /exact verified catalog session/)
})

test('terminal ABORT force-closes a forever-undrained channel within the exact deadline', (t) => {
  const clock = fakeClock()
  const events = []
  const c = controller({
    abortDrainTimeoutMs: 100,
    setTimeout: (fn, ms) => clock.setTimeout(fn, ms),
    clearTimeout: timer => clock.clearTimeout(timer)
  })
  const state = {
    closed: false,
    closeAfterDrain: false,
    abortCloseTimer: null,
    api: {
      drained: false,
      sendAbort () { events.push('abort') },
      close () { events.push('close') }
    }
  }
  t.is(c._sendAbortBeforeClose(state, {}), true)
  clock.tick(99)
  t.alike(events, ['abort'], 'ABORT is handed to transport before close')
  clock.tick(1)
  t.alike(events, ['abort', 'close'], 'deadline releases a permanently backpressured channel slot')

  const drained = {
    closed: false,
    closeAfterDrain: false,
    abortCloseTimer: null,
    api: {
      drained: false,
      sendAbort () { events.push('drained-abort') },
      close () { events.push('drained-close') }
    }
  }
  c._sendAbortBeforeClose(drained, {})
  c._channelDrained(drained)
  clock.tick(100)
  t.is(events.filter(event => event === 'drained-close').length, 1, 'drain cancels the force-close timer')
})

test('257 sequential completed peers release and remove durable state across controller restart', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-controller-churn-')))
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await rm(root, { recursive: true, force: true })
  })
  let factory = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(factory)
  const c = controller({
    stageFactory: factory,
    onCatalogActionPage: async () => ({ acted: 0 })
  })
  c._actionScheduler = { trigger () {} }

  for (let i = 1; i <= APP_CATALOG_LIMITS.maxInboundPeers + 1; i++) {
    if (i === 129) {
      await factory.stop()
      factory = new AppCatalogDiskStageFactory({ rootDir: root })
      factories.push(factory)
      await factory.ready()
      c.stageFactory = factory
      t.alike(await readdir(join(root, 'peers')), [], 'restart adopts the already-drained retained set')
    }
    const remote = peer(i)
    const value = await emptyCommittedCatalog(factory, remote, i)
    c._catalogCommitted(value)
    await value.catalog.release()
    await c._advanceAction()
    await c._drainCatalogReleases()
  }
  t.alike(await readdir(join(root, 'peers')), [], '257th sequential peer cannot create a retained-peer admission DoS')
  t.alike(await readdir(join(root, 'snapshots')), [], 'final action cleanup reclaims every owned snapshot')
})

test('canonical catalog ingress enforces field and one-PAGE row bounds', (t) => {
  t.exception(
    () => assertAppRegistryCatalogIngress('e'.repeat(64), {
      type: 'app',
      appId: 'oversize',
      mountPath: `/${'x'.repeat(APP_CATALOG_LIMITS.maxPayloadBytes)}`
    }),
    /byte length is outside|CATALOG_ENTRY_TOO_LARGE|wire limit|payload/
  )
})
