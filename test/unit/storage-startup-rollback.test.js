import test from 'brittle'
import { access, mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { BareRelay } from '../../packages/core/core/relay-node/bare-relay.js'
import { AppLifecycle } from '../../packages/core/core/relay-node/app-lifecycle.js'
import { StorageAdmissionAuthority } from '../../packages/core/config/storage-admission-authority.js'

const JOURNAL_BOUND = 16 * 1024 * 1024
const LIFECYCLE_ONE_SHOT_TIMERS = [
  '_registryInitialScanTimer',
  '_acceptanceReconcileTimer',
  '_coldStartPrimerTimer',
  '_anchorInitialTimer',
  '_repairInitialTimer',
  '_custodyExpiryInitialTimer',
  '_catalogBroadcastTimer'
]

function minimalNodeForShutdown (serviceRegistry, events) {
  const node = Object.create(RelayNode.prototype)
  const admission = new StorageAdmissionAuthority({ storage: '/mock', maxStorageBytes: 1024 * 1024 }, {
    recoveryKinds: []
  })
  const closeMutations = admission.closeMutations.bind(admission)
  admission.closeMutations = reason => {
    events.push('authority-close')
    return closeMutations(reason)
  }
  Object.assign(node, {
    running: true,
    _starting: false,
    _startupRollbackPending: false,
    _stopRequested: false,
    _storageIngressReady: true,
    _ownerOperations: new WeakMap(),
    _ownerDeadline: null,
    _scope: null,
    _epochDiscoveryTopics: new Map(),
    _retiringEpochDiscoveryHandles: new Set(),
    _relayDiscoveryHandle: null,
    _foundationDiscoveryHandle: null,
    config: { storage: '/mock', shutdownTimeoutMs: 1000 },
    storageAdmission: admission,
    serviceRegistry,
    serviceProtocol: null,
    appLifecycle: { seededApps: new Map() },
    bootstrapCache: { stop () {}, async save () {} },
    _catalogPeerThrottle: new Map(),
    _replicationHealth: new Map(),
    store: {
      closed: false,
      async close () { events.push('store-close'); this.closed = true }
    }
  })
  return node
}

function minimalBareForShutdown (events) {
  const relay = Object.create(BareRelay.prototype)
  const admission = new StorageAdmissionAuthority({ storage: '/mock', maxStorageBytes: 1024 * 1024 }, {
    recoveryKinds: []
  })
  Object.assign(relay, {
    running: true,
    _starting: false,
    _startupRollbackPending: false,
    _stopRequested: false,
    _storageIngressReady: true,
    _ownerOperations: new WeakMap(),
    _ownerDeadline: null,
    _epochDiscoveryTimer: null,
    _epochDiscoveryTopics: new Map(),
    _retiringEpochDiscoveryHandles: new Set(),
    _discovery: null,
    _foundationDiscovery: null,
    _regionDiscovery: null,
    config: { storage: '/mock', shutdownTimeoutMs: 1000 },
    storageAdmission: admission,
    serviceRegistry: null,
    serviceProtocol: null,
    appRegistry: null,
    store: {
      async close () { events.push('bare-store-close') }
    }
  })
  return relay
}

test('RelayNode owns every deferred lifecycle callback and rejects callbacks from an old start', (t) => {
  const nativeSetTimeout = globalThis.setTimeout
  const nativeClearTimeout = globalThis.clearTimeout
  const scheduled = []
  const cleared = []
  globalThis.setTimeout = (fn, delay) => {
    const timer = { fn, delay, cleared: false }
    scheduled.push(timer)
    return timer
  }
  globalThis.clearTimeout = (timer) => {
    timer.cleared = true
    cleared.push(timer)
  }

  try {
    const node = Object.create(RelayNode.prototype)
    const firstScope = { aborted: false }
    Object.assign(node, {
      running: true,
      _stopRequested: false,
      _scope: firstScope
    })
    for (const field of LIFECYCLE_ONE_SHOT_TIMERS) node[field] = null

    let staleRuns = 0
    const firstTimers = []
    for (const field of LIFECYCLE_ONE_SHOT_TIMERS) {
      firstTimers.push(node._setLifecycleTimer(field, 5000, () => { staleRuns++ }))
      t.ok(node[field], `${field} is retained by the node`)
    }

    node.running = false
    node._stopRequested = true
    firstScope.aborted = true
    node._scope = null
    for (const timer of firstTimers) timer.fn()
    t.is(staleRuns, 0, 'stopped lifecycle callbacks cannot run')
    for (const field of LIFECYCLE_ONE_SHOT_TIMERS) t.is(node[field], null, `${field} releases ownership after firing`)

    const secondScope = { aborted: false }
    node.running = true
    node._stopRequested = false
    node._scope = secondScope
    let replacementRuns = 0
    for (const field of LIFECYCLE_ONE_SHOT_TIMERS) {
      const replaced = node._setLifecycleTimer(field, 5000, () => { staleRuns++ })
      const replacement = node._setLifecycleTimer(field, 5000, () => { replacementRuns++ })
      t.ok(replaced.cleared, `${field} replacement clears the previous timer`)
      replaced.fn()
      t.is(node[field], replacement, `${field} ignores an old-start callback`)
      replacement.fn()
      t.is(node[field], null, `${field} releases the replacement after firing`)
    }
    t.is(staleRuns, 0, 'replaced callbacks never cross the start boundary')
    t.is(replacementRuns, LIFECYCLE_ONE_SHOT_TIMERS.length, 'each current lifecycle callback runs once')
    t.is(cleared.length, LIFECYCLE_ONE_SHOT_TIMERS.length, 'every replacement retires exactly one predecessor')
  } finally {
    globalThis.setTimeout = nativeSetTimeout
    globalThis.clearTimeout = nativeClearTimeout
    for (const timer of scheduled) {
      if (!timer.cleared) timer.cleared = true
    }
  }
})

test('storage ingress stays closed until recovery inventories seal', async (t) => {
  const lifecycle = new AppLifecycle({ _storageIngressReady: false })
  const failure = await Promise.allSettled([
    lifecycle.seedApp('a'.repeat(64), { maxStorage: 1024 })
  ])
  t.is(failure[0].reason.code, 'STORAGE_RECOVERY_INVENTORY_PENDING')

  for (const Relay of [RelayNode, BareRelay]) {
    const relay = Object.create(Relay.prototype)
    relay._storageIngressReady = false
    relay.store = { replicate () { throw new Error('must not replicate before inventory seal') } }
    let destroyed = 0
    relay._onConnection({ destroy () { destroyed++ } }, {})
    t.is(destroyed, 1, `${Relay.name} rejects a pre-seal connection`)
  }
})

test('custom storage path must pre-exist; missing mount-shaped path is never auto-created', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'storage-mount-safety-'))
  const nodePath = join(base, 'intended-node-mount')
  const node = new RelayNode({ storage: nodePath, enableAPI: false, enableRelay: false })
  const nodeFailure = await Promise.allSettled([node.start()])
  t.is(nodeFailure[0].reason.code, 'STORAGE_FILESYSTEM_UNRESOLVED')
  await t.exception(access(nodePath), /ENOENT/, 'Node custom path remains absent')

  const barePath = join(base, 'intended-bare-mount')
  const bare = new BareRelay({ storage: barePath, enableHttp: false })
  const bareFailure = await Promise.allSettled([bare.start()])
  t.is(bareFailure[0].reason.code, 'STORAGE_FILESYSTEM_UNRESOLVED')
  await t.exception(access(barePath), /ENOENT/, 'Bare custom path remains absent')
  await rm(base, { recursive: true, force: true })
})

test('corrupt drive inventory starts no API, service, or connection ingress', async (t) => {
  for (const [name, Relay, opts] of [
    ['node', RelayNode, { enableAPI: true, apiPort: 0, enableRelay: false }],
    ['bare', BareRelay, { enableHttp: false }]
  ]) {
    const storage = await mkdtemp(join(tmpdir(), `${name}-corrupt-drive-inventory-`))
    await writeFile(join(storage, 'app-registry.json'), JSON.stringify([
      { appKey: 'A'.repeat(64), maxStorage: 1024 }
    ]))
    const relay = new Relay({ storage, ...opts })
    await t.exception(relay.start(), /APP_REGISTRY_INVENTORY_FAILED|invalid-app-key/)
    t.is(relay._storageIngressReady, false)
    t.absent(relay.api, `${name}: management API never starts`)
    t.absent(relay.gatewayServer, `${name}: public gateway never starts`)
    t.absent(relay.serviceRegistry, `${name}: storage-producing services never start`)
    await rm(storage, { recursive: true, force: true })
  }
})

test('RelayNode failed start stops an already-started storage service before Corestore teardown', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'node-startup-rollback-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const node = new RelayNode({
    storage,
    enableAPI: false,
    enableRelay: false,
    enableServices: true,
    plugins: ['outboxlog'],
    outboxlog: { journal: 'hypercore', maxJournalStorageBytes: JOURNAL_BOUND },
    lease: { enabled: true },
    leaseProvider: {}
  })

  await t.exception(node.start(), /lookupInvoice/)
  t.is(node.running, false)
  t.is(node.storageAdmission.acceptingMutations, false)
  t.is(node.storageAdmission.snapshot().activeMutations, 0)
  t.absent(node.serviceRegistry, 'started services were stopped and detached')
  t.absent(node.serviceProtocol)
  t.absent(node.swarm)
  t.absent(node.seeder)
  t.ok(node.store.closed, 'Corestore closes only after service and authority drain')
  for (const field of LIFECYCLE_ONE_SHOT_TIMERS) {
    t.is(node[field], null, `${field} is cleared by startup rollback`)
  }
})

test('startup rollback retains swarm and store when discovery retirement fails', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'node-startup-discovery-rollback-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const node = new RelayNode({
    storage,
    enableAPI: false,
    enableRelay: false,
    privacy: { rotateDiscoveryTopic: 'additive' },
    lease: { enabled: true },
    leaseProvider: {}
  })
  const destroyDiscoveryHandles = node._destroyDiscoveryHandles.bind(node)
  node._destroyDiscoveryHandles = async () => { throw new Error('injected discovery rollback failure') }

  const failure = await Promise.allSettled([node.start()])
  t.is(failure[0].reason.code, 'STORAGE_WRITER_QUIESCE_FAILED')
  t.ok(/discovery rollback failure/.test(failure[0].reason.cause.message))
  t.is(node._startupRollbackPending, true)
  t.ok(node.swarm, 'swarm remains owned for a later retirement retry')
  t.is(node.store.closed, false, 'store remains open while discovery teardown is unsettled')

  node._destroyDiscoveryHandles = destroyDiscoveryHandles
  await node.stop()
  t.ok(node.store.closed)
  t.is(node._startupRollbackPending, false)
})

test('BareRelay shutdown awaits discovery retirement before swarm and store teardown', async (t) => {
  const events = []
  const relay = minimalBareForShutdown(events)
  let settleDiscovery
  const discoverySettled = new Promise(resolve => { settleDiscovery = resolve })
  relay._discovery = {
    async destroy () {
      events.push('bare-discovery-destroy-start')
      await discoverySettled
      events.push('bare-discovery-destroy-done')
    }
  }
  relay.swarm = {
    async destroy () { events.push('bare-swarm-destroy') }
  }

  const stopping = relay.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('bare-discovery-destroy-start'))
  t.absent(events.includes('bare-swarm-destroy'), 'Bare swarm stays live until discovery retirement settles')
  t.absent(events.includes('bare-store-close'))

  settleDiscovery()
  await stopping
  t.alike(events.slice(-4), [
    'bare-discovery-destroy-start',
    'bare-discovery-destroy-done',
    'bare-swarm-destroy',
    'bare-store-close'
  ])
})

test('BareRelay failed discovery retirement keeps handle, swarm, and store retryable', async (t) => {
  const events = []
  const relay = minimalBareForShutdown(events)
  let rejectDestroy = true
  const handle = {
    async destroy () {
      events.push('bare-discovery-destroy')
      if (rejectDestroy) throw new Error('injected bare discovery retirement failure')
    }
  }
  relay._discovery = handle
  relay.swarm = {
    async destroy () { events.push('bare-swarm-destroy') }
  }

  const failure = await Promise.allSettled([relay.stop()])
  t.is(failure[0].reason.code, 'STORAGE_WRITER_QUIESCE_FAILED')
  t.ok(/bare discovery retirement failure/.test(failure[0].reason.cause.message))
  t.is(relay._discovery, handle, 'failed Bare handle remains owned for retry')
  t.absent(events.includes('bare-swarm-destroy'))
  t.absent(events.includes('bare-store-close'))

  rejectDestroy = false
  await relay.stop()
  t.is(relay._discovery, null)
  t.ok(events.includes('bare-swarm-destroy'))
  t.ok(events.includes('bare-store-close'))
})

test('BareRelay failed swarm destruction keeps swarm and store owned for retry', async (t) => {
  const events = []
  const relay = minimalBareForShutdown(events)
  let fail = true
  const swarm = {
    async destroy () {
      events.push('bare-swarm-destroy')
      if (fail) throw new Error('injected bare swarm destroy failure')
    }
  }
  relay.swarm = swarm

  await t.exception(relay.stop(), /injected bare swarm destroy failure/)
  t.is(relay.swarm, swarm)
  t.absent(events.includes('bare-store-close'))

  fail = false
  await relay.stop()
  t.is(relay.swarm, null)
  t.ok(events.includes('bare-store-close'))
})

test('BareRelay failed late start rolls back swarm, seeder, services, and store', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'bare-startup-rollback-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  class FailingBareRelay extends BareRelay {
    _joinEpochDiscoveryTopics () { throw new Error('injected post-service startup failure') }
  }
  const relay = new FailingBareRelay({
    storage,
    enableHttp: false,
    privacy: { rotateDiscoveryTopic: 'additive' }
  })

  await t.exception(relay.start(), /injected post-service startup failure/)
  t.is(relay.running, false)
  t.is(relay.storageAdmission.acceptingMutations, false)
  t.is(relay.storageAdmission.snapshot().activeMutations, 0)
  t.absent(relay.serviceRegistry)
  t.absent(relay.swarm)
  t.absent(relay.seeder)
  t.absent(relay.store)
})

test('Node and Bare stop during start never claim running or close over active mutations', async (t) => {
  const nodeStorage = await mkdtemp(join(tmpdir(), 'node-start-stop-overlap-'))
  const node = new RelayNode({ storage: nodeStorage, enableAPI: false, enableRelay: false })
  const nodeStart = node.start()
  const nodeStop = node.stop()
  await Promise.allSettled([nodeStart, nodeStop])
  t.is(node.running, false)
  t.is(node.storageAdmission.acceptingMutations, false)
  t.is(node.storageAdmission.snapshot().activeMutations, 0)
  t.ok(node.store.closed)

  const bareStorage = await mkdtemp(join(tmpdir(), 'bare-start-stop-overlap-'))
  const bare = new BareRelay({ storage: bareStorage, enableHttp: false })
  const bareStart = bare.start()
  const bareStop = bare.stop()
  await Promise.allSettled([bareStart, bareStop])
  t.is(bare.running, false)
  t.is(bare.storageAdmission.acceptingMutations, false)
  t.is(bare.storageAdmission.snapshot().activeMutations, 0)
  t.absent(bare.store)

  await rm(nodeStorage, { recursive: true, force: true })
  await rm(bareStorage, { recursive: true, force: true })
})

test('failed-start terminal drain settles lifecycle waiters but preserves Corestore until retry', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'node-terminal-startup-drain-'))
  const node = new RelayNode({
    storage,
    enableAPI: false,
    enableRelay: false,
    shutdownTimeoutMs: 10
  })
  const originalBeginRecovery = node.storageAdmission.beginRecovery.bind(node.storageAdmission)
  let beginRecoveryCalls = 0
  let pendingHandoff = null
  node.storageAdmission.beginRecovery = (...args) => {
    beginRecoveryCalls++
    const result = originalBeginRecovery(...args)
    node.storageAdmission.adoptRecovery('outboxlog:pending-writer', 1024 * 1024, { kind: 'outboxlog' })
    pendingHandoff = node.storageAdmission.issueOwnedHandoff('outboxlog:pending-writer')
    return result
  }
  let settle
  node.storageAdmission.trackMutation(new Promise(resolve => { settle = resolve }))

  const start = node.start()
  const stop = node.stop()
  const [started, stopped] = await Promise.allSettled([start, stop])
  t.is(started.status, 'rejected')
  t.is(started.reason.code, 'STORAGE_MUTATION_DRAIN_TIMEOUT')
  t.is(stopped.status, 'rejected', 'concurrent stop observes the terminal rollback failure')
  t.is(node._starting, false, 'failed rollback still settles lifecycle state')
  t.is(node._startupRollbackPending, true)
  t.is(node.store.closed, false, 'unsettled writer prevents Corestore teardown')
  t.is(beginRecoveryCalls, 1)
  const retry = await Promise.allSettled([node.start()])
  t.is(retry[0].reason.code, 'STORAGE_STARTUP_ROLLBACK_PENDING')
  t.is(beginRecoveryCalls, 1, 'retry cannot clear liability through beginRecovery')
  t.is(node.storageAdmission.snapshot().activeMutations, 1, 'old writer remains tracked')
  t.ok(node.storageAdmission.get('outboxlog:pending-writer'), 'old commitment remains installed')
  t.is(node.storageAdmission.releaseOwnedHandoff(pendingHandoff), true, 'old opaque lease was not silently cleared')

  settle()
  await node.storageAdmission.drainMutations({ timeoutMs: 100 })
  node.config.shutdownTimeoutMs = 30_000
  await node.stop()
  t.ok(node.store.closed, 'a later stop safely completes after real settlement')
  t.is(node._startupRollbackPending, false)
  await rm(storage, { recursive: true, force: true })
})

test('BareRelay terminal rollback blocks a second start until old writer settlement', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'bare-terminal-startup-drain-'))
  const relay = new BareRelay({ storage, enableHttp: false, shutdownTimeoutMs: 10 })
  const originalBeginRecovery = relay.storageAdmission.beginRecovery.bind(relay.storageAdmission)
  let beginRecoveryCalls = 0
  let pendingHandoff = null
  relay.storageAdmission.beginRecovery = (...args) => {
    beginRecoveryCalls++
    const result = originalBeginRecovery(...args)
    relay.storageAdmission.adoptRecovery('outboxlog:pending-writer', 1024 * 1024, { kind: 'outboxlog' })
    pendingHandoff = relay.storageAdmission.issueOwnedHandoff('outboxlog:pending-writer')
    return result
  }
  let settle
  relay.storageAdmission.trackMutation(new Promise(resolve => { settle = resolve }))

  const [started, stopped] = await Promise.allSettled([relay.start(), relay.stop()])
  t.is(started.status, 'rejected')
  t.is(started.reason.code, 'STORAGE_MUTATION_DRAIN_TIMEOUT')
  t.is(stopped.status, 'rejected')
  t.is(relay._startupRollbackPending, true)
  t.ok(relay.store, 'Corestore remains owned while the writer can settle')
  const retry = await Promise.allSettled([relay.start()])
  t.is(retry[0].reason.code, 'STORAGE_STARTUP_ROLLBACK_PENDING')
  t.is(beginRecoveryCalls, 1)
  t.is(relay.storageAdmission.snapshot().activeMutations, 1)
  t.ok(relay.storageAdmission.get('outboxlog:pending-writer'))
  t.is(relay.storageAdmission.releaseOwnedHandoff(pendingHandoff), true)

  settle()
  await relay.storageAdmission.drainMutations({ timeoutMs: 100 })
  relay.config.shutdownTimeoutMs = 30_000
  await relay.stop()
  t.absent(relay.store)
  t.is(relay._startupRollbackPending, false)
  await rm(storage, { recursive: true, force: true })
})

test('regular shutdown quiesces providers before sealing and drains late append before store close', async (t) => {
  const events = []
  let settle
  const lateAppend = new Promise(resolve => { settle = resolve })
  let node = null
  const serviceRegistry = {
    async stopAll (opts) {
      t.is(opts.throwOnError, true)
      events.push('provider-stop')
      node.storageAdmission.trackMutation(lateAppend)
    }
  }
  node = minimalNodeForShutdown(serviceRegistry, events)
  for (const field of LIFECYCLE_ONE_SHOT_TIMERS) {
    node[field] = setTimeout(() => t.fail(`${field} survived shutdown`), 60_000)
  }

  const stopping = node.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events.slice(0, 2), ['provider-stop', 'authority-close'])
  t.is(node.store.closed, false, 'late append retains Corestore during authority drain')
  t.is(node.storageAdmission.snapshot().activeMutations, 1)
  settle()
  await stopping
  t.alike(events, ['provider-stop', 'authority-close', 'store-close'])
  t.ok(node.store.closed)
  t.is(node.storageAdmission.snapshot().activeMutations, 0)
  for (const field of LIFECYCLE_ONE_SHOT_TIMERS) {
    t.is(node[field], null, `${field} is cleared by regular shutdown`)
  }
})

test('provider quiescence failure seals admission but retains store and debt', async (t) => {
  const events = []
  const serviceRegistry = {
    async stopAll () {
      events.push('provider-stop')
      throw new Error('injected provider stop failure')
    }
  }
  const node = minimalNodeForShutdown(serviceRegistry, events)
  node.storageAdmission.adoptRecovery('workload:pending', 4096, { kind: 'workload' })

  const failure = await Promise.allSettled([node.stop()])
  t.is(failure[0].reason.code, 'STORAGE_WRITER_QUIESCE_FAILED')
  t.alike(events, ['provider-stop', 'authority-close'])
  t.is(node.store.closed, false)
  t.is(node.storageAdmission.acceptingMutations, false)
  t.is(node.storageAdmission.fatalReason, 'storage-writer-quiesce-failed')
  t.ok(node.storageAdmission.get('workload:pending'), 'debt remains installed')
})

test('regular shutdown awaits discovery retirement before swarm and store teardown', async (t) => {
  const events = []
  const node = minimalNodeForShutdown(null, events)
  let settleDiscovery
  const discoverySettled = new Promise(resolve => { settleDiscovery = resolve })
  node._relayDiscoveryHandle = {
    async destroy () {
      events.push('discovery-destroy-start')
      await discoverySettled
      events.push('discovery-destroy-done')
    }
  }
  node.swarm = {
    async destroy () { events.push('swarm-destroy') }
  }

  const stopping = node.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('discovery-destroy-start'))
  t.absent(events.includes('swarm-destroy'), 'swarm stays live until discovery retirement settles')
  t.is(node.store.closed, false)

  settleDiscovery()
  await stopping
  t.alike(events.slice(-4), [
    'discovery-destroy-start',
    'discovery-destroy-done',
    'swarm-destroy',
    'store-close'
  ])
})

test('failed discovery retirement keeps swarm and store retryable', async (t) => {
  const events = []
  const node = minimalNodeForShutdown(null, events)
  let rejectDestroy = true
  const handle = {
    async destroy () {
      events.push('discovery-destroy')
      if (rejectDestroy) throw new Error('injected discovery retirement failure')
    }
  }
  node._relayDiscoveryHandle = handle
  node.swarm = {
    async destroy () { events.push('swarm-destroy') }
  }

  await t.exception(node.stop(), /injected discovery retirement failure/)
  t.is(node._relayDiscoveryHandle, handle, 'failed handle remains owned for retry')
  t.absent(events.includes('swarm-destroy'))
  t.is(node.store.closed, false)

  rejectDestroy = false
  await node.stop()
  t.is(node._relayDiscoveryHandle, null)
  t.ok(events.includes('swarm-destroy'))
  t.ok(node.store.closed)
})

test('rolled epoch discovery retirement remains tracked until its async destroy settles', async (t) => {
  const node = minimalNodeForShutdown(null, [])
  let settle
  const gate = new Promise(resolve => { settle = resolve })
  node._queueEpochDiscoveryDestroy({
    async destroy () { await gate }
  })

  const draining = node._destroyDiscoveryHandles(1000)
  await new Promise(resolve => setImmediate(resolve))
  t.is(node._retiringEpochDiscoveryHandles.size, 1, 'rolled handle stays owned while destroy is pending')
  settle()
  await draining
  t.is(node._retiringEpochDiscoveryHandles.size, 0)
})

test('regular shutdown retains store until delayed swarm destruction settles', async (t) => {
  const events = []
  const node = minimalNodeForShutdown(null, events)
  let settleSwarm
  const gate = new Promise(resolve => { settleSwarm = resolve })
  node.swarm = {
    async destroy () {
      events.push('swarm-destroy-start')
      await gate
      events.push('swarm-destroy-done')
    }
  }

  const stopping = node.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('swarm-destroy-start'))
  t.is(node.store.closed, false)
  settleSwarm()
  await stopping
  t.alike(events.slice(-3), ['swarm-destroy-start', 'swarm-destroy-done', 'store-close'])
})

test('failed swarm destruction keeps swarm and store owned for retry', async (t) => {
  const node = minimalNodeForShutdown(null, [])
  let fail = true
  const swarm = {
    async destroy () {
      if (fail) throw new Error('injected swarm destroy failure')
    }
  }
  node.swarm = swarm

  await t.exception(node.stop(), /injected swarm destroy failure/)
  t.is(node.swarm, swarm)
  t.is(node.store.closed, false)

  fail = false
  await node.stop()
  t.is(node.swarm, null)
  t.ok(node.store.closed)
})

test('RelayNode destroys anchor custody and publish protocols and retains failed owner', async (t) => {
  const node = Object.create(RelayNode.prototype)
  const events = []
  let rejectCustody = true
  const custody = {
    destroy () {
      events.push('custody')
      if (rejectCustody) throw new Error('injected custody teardown failure')
    }
  }
  Object.assign(node, {
    _ownerOperations: new WeakMap(),
    _ownerDeadline: null,
    _anchorProtocol: { destroy () { events.push('anchor') } },
    _custodyProtocol: custody,
    _publishProtocol: { destroy () { events.push('publish') } }
  })

  await t.exception(
    node._destroyProtocolHandlers(100, ['_anchorProtocol', '_custodyProtocol', '_publishProtocol']),
    /injected custody teardown failure/
  )
  t.alike(events, ['anchor', 'custody', 'publish'])
  t.is(node._anchorProtocol, null)
  t.is(node._custodyProtocol, custody, 'failed protocol remains owned')
  t.is(node._publishProtocol, null)

  rejectCustody = false
  await node._destroyProtocolHandlers(100, ['_custodyProtocol'])
  t.is(node._custodyProtocol, null)
})
