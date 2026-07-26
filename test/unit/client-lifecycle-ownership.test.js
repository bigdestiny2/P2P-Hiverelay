import test from 'brittle'
import { EventEmitter } from 'events'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import hypercoreCrypto from 'hypercore-crypto'
import { HiveRelayClient } from 'p2p-hiverelay-client'

class FakeSwarm extends EventEmitter {
  constructor (makeHandle) {
    super()
    this.makeHandle = makeHandle
    this.connections = new Set()
  }

  join (topic, opts) { return this.makeHandle(topic, opts) }
  async flush () {}
}

function readerHarness (makeHandle) {
  const store = {}
  const swarm = new FakeSwarm(makeHandle)
  const client = new HiveRelayClient({ store, swarm, autoDiscover: false })
  client._started = true
  client._lifecycleAbort = new AbortController()
  return client
}

test('client concurrent same-key open shares one drive owner and discovery session', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 1)
  let settle
  const gate = new Promise(resolve => { settle = resolve })
  const drive = { key }
  let opens = 0
  client._open = async () => {
    opens++
    await gate
    client.drives.set(key.toString('hex'), drive)
    return drive
  }

  const first = client.open(key, { wait: false })
  const second = client.open(key, { wait: false })
  t.is(first, second, 'same-key callers share the in-flight owner promise')
  settle()
  const [left, right] = await Promise.all([first, second])
  t.is(left, right, 'both callers receive one drive instance')
  t.is(opens, 1, 'one tentative drive owner is constructed')
  client.drives.clear()
  await client.destroy()
})

test('client failed discovery flush destroys tentative drive ownership', async (t) => {
  let destroys = 0
  let closes = 0
  const client = readerHarness(() => ({
    async destroy () { destroys++ }
  }))
  const key = '2'.repeat(64)
  const handle = client._joinDriveDiscovery(key, Buffer.alloc(32, 2), { server: false, client: true })
  t.ok(handle)
  const drive = { async close () { closes++ } }

  await t.exception(
    client._failOpen(key, drive, new Error('injected flush failure')),
    /injected flush failure/
  )
  t.is(destroys, 1, 'failed open destroys exact tentative discovery session')
  t.is(closes, 1, 'failed open closes tentative drive')
  t.is(client.drives.size, 0, 'failed tentative drive is not published as live')
  await client.destroy()
})

test('client destroy aborts a hung open flush and drains it before teardown', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 3)
  client._open = async () => {
    await client._raceLifecycle(new Promise(() => {}), 60_000, 'drive discovery flush')
  }

  const opening = client.open(key, { wait: false })
  await new Promise(resolve => setImmediate(resolve))
  await client.destroy()
  await t.exception(opening, /aborted/)
  t.is(client._operations.size, 0)
})

test('client owns share-bundle core and discovery until destroy', async (t) => {
  const events = []
  const core = {
    key: Buffer.alloc(32, 3),
    discoveryKey: Buffer.alloc(32, 4),
    async ready () { events.push('core-ready') },
    async append () { events.push('core-append') },
    async close () { events.push('core-close') }
  }
  const store = { get () { return core } }
  const swarm = new FakeSwarm(() => ({
    async destroy () { events.push('discovery-destroy') }
  }))
  const client = new HiveRelayClient({ store, swarm, autoDiscover: false })
  client._started = true
  client._lifecycleAbort = new AbortController()

  const key = await client._writeShareBundle({ public: true })
  t.is(client._shareBundleCores.get(key)?.core, core)
  await client.destroy()
  t.alike(events, [
    'core-ready',
    'core-append',
    'discovery-destroy',
    'core-close'
  ])
})

test('client-owned swarm and store are nulled so restart creates fresh owners', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'hiverelay-client-restart-'))
  const client = new HiveRelayClient(storage, { autoDiscover: false })
  t.teardown(async () => {
    try { await client.destroy() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })

  await client.start()
  const firstSwarm = client.swarm
  const firstStore = client.store
  await client.destroy()
  t.is(client.swarm, null)
  t.is(client.store, null)

  await client.start()
  t.not(client.swarm, firstSwarm, 'restart owns a fresh swarm')
  t.not(client.store, firstStore, 'restart owns a fresh store')
  await client.destroy()
})

test('client close waits an in-flight open and closes the published owner exactly once', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 6)
  const keyHex = key.toString('hex')
  let releaseOpen = null
  const openGate = new Promise(resolve => { releaseOpen = resolve })
  let closes = 0
  const drive = { async close () { closes++ } }
  client._open = async () => {
    await openGate
    client.drives.set(keyHex, drive)
    return drive
  }

  const opening = client.open(key, { wait: false })
  const closing = client.closeDrive(key)
  let closeSettled = false
  closing.then(() => { closeSettled = true })
  await new Promise(resolve => setTimeout(resolve, 0))
  t.is(closeSettled, false, 'close remains behind the tentative open owner')
  releaseOpen()
  await Promise.all([opening, closing])
  t.is(closes, 1)
  t.absent(client.drives.has(keyHex))
  await client.destroy()
})

test('client open waits an in-flight close and returns a fresh drive', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 7)
  const keyHex = key.toString('hex')
  let releaseClose = null
  const closeGate = new Promise(resolve => { releaseClose = resolve })
  const oldDrive = { async close () { await closeGate } }
  const freshDrive = { fresh: true }
  client.drives.set(keyHex, oldDrive)
  let opens = 0
  client._open = async () => {
    opens++
    client.drives.set(keyHex, freshDrive)
    return freshDrive
  }

  const closing = client.closeDrive(key)
  const opening = client.open(key, { wait: false })
  await new Promise(resolve => setTimeout(resolve, 0))
  t.is(opens, 0, 'reopen does not race the old drive close')
  releaseClose()
  const [, reopened] = await Promise.all([closing, opening])
  t.is(reopened, freshDrive)
  t.is(opens, 1)
  client.drives.clear()
  await client.destroy()
})

test('client failed start transaction settles registry, listener, and discovery before retry', async (t) => {
  let discoveryDestroys = 0
  let registryStops = 0
  const swarm = new FakeSwarm(() => ({ async destroy () { discoveryDestroys++ } }))
  const client = new HiveRelayClient({ store: {}, swarm, autoDiscover: false })
  const connectionHandler = () => {}
  client._start = async () => {
    client._lifecycleAbort = new AbortController()
    client._registry = { async stop () { registryStops++ } }
    client._connectionHandler = connectionHandler
    swarm.on('connection', connectionHandler)
    client._discoveryTopic = swarm.join(Buffer.alloc(32), { client: true })
    throw new Error('injected late start failure')
  }

  await t.exception(client.start(), /injected late start failure/)
  t.is(registryStops, 1)
  t.is(discoveryDestroys, 1)
  t.is(swarm.listenerCount('connection'), 0)
  t.is(client._registry, null)
  t.is(client._discoveryTopic, null)
  t.is(client._stopping, false, 'successful rollback reopens start admission')
  await client.destroy()
})

test('client exact-owner lane never closes beneath a timed-out ready operation', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  client._destroyTimeout = 5
  const owner = {}
  let releaseReady = null
  const readyGate = new Promise(resolve => { releaseReady = resolve })
  let closes = 0
  await t.exception(
    client._awaitOwnerOperation('owner-ready', owner, () => readyGate),
    /timed out/
  )
  const closing = client._awaitOwnerOperation('owner-close', owner, async () => { closes++ })
  await new Promise(resolve => setTimeout(resolve, 0))
  t.is(closes, 0, 'close remains chained behind retained ready')
  releaseReady()
  await closing
  t.is(closes, 1)
  await client.destroy()
})

test('client real open cancellation retains drive.ready before exact close', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 18)
  let releaseReady = null
  const readyGate = new Promise(resolve => { releaseReady = resolve })
  let closes = 0
  const drive = {
    async ready () { await readyGate },
    async close () { closes++ }
  }
  client._createOpenDrive = () => drive

  const opening = client.open(key, { wait: false, readyTimeout: 60_000 })
  await new Promise(resolve => setImmediate(resolve))
  const destroying = client.destroy()
  await new Promise(resolve => setImmediate(resolve))
  t.is(closes, 0, 'destroy cannot close beneath the retained real drive.ready')
  releaseReady()
  await t.exception(opening, /aborted/)
  await destroying
  t.is(closes, 1, 'exact drive closes once after ready settles')
  t.is(client._operations.size, 0)
})

test('client queued discovery replacement destroys behind retained exact flush', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  let releaseFlush = null
  const flushGate = new Promise(resolve => { releaseFlush = resolve })
  let destroys = 0
  const handle = { async destroy () { destroys++ } }
  client._ownerOperation('discovery-flush', handle, () => flushGate)
  client._queueDiscoveryDestroy(handle)
  const retiring = [...client._retiringDiscoveryHandles][0]

  await new Promise(resolve => setImmediate(resolve))
  t.is(destroys, 0, 'replacement destroy cannot overtake retained flush')
  releaseFlush()
  await retiring.promise
  t.is(destroys, 1, 'exact discovery handle destroys once after flush settles')
  await client.destroy()
})

test('client tracked seed retains registry publish before registry stop', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  client.keyPair = hypercoreCrypto.keyPair()
  const events = []
  let releasePublish = null
  const publishGate = new Promise(resolve => { releasePublish = resolve })
  client._registry = {
    async publishRequest () {
      events.push('registry-publish-start')
      await publishGate
      events.push('registry-publish-settled')
    },
    async stop () { events.push('registry-stop') }
  }

  const seeding = client.seed(Buffer.alloc(32, 19), {
    maxStorage: 1024,
    replicas: 1,
    timeout: 10,
    retryPersistent: false
  })
  await new Promise(resolve => setImmediate(resolve))
  const destroying = client.destroy()
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events, ['registry-publish-start'], 'registry stop cannot overtake retained publish')
  releasePublish()
  await t.exception(seeding, /aborted/)
  await destroying
  t.alike(events, ['registry-publish-start', 'registry-publish-settled', 'registry-stop'])
  t.is(client._operations.size, 0)
})

test('client failed drive close retains drive and fork listeners for retry', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = '8'.repeat(64)
  let rejectClose = true
  let removals = 0
  const core = { removeListener () { removals++ } }
  const drive = {
    async close () {
      if (rejectClose) throw new Error('injected drive close failure')
    }
  }
  client.drives.set(key, drive)
  client._driveForkListeners = new Map([[key, {
    core,
    onTruncate: () => {},
    onVerifyError: () => {}
  }]])

  await t.exception(client.closeDrive(key), /injected drive close failure/)
  t.is(client.drives.get(key), drive)
  t.ok(client._driveForkListeners.has(key))
  t.is(removals, 0, 'listeners remain attached to the retained owner')
  rejectClose = false
  await client.closeDrive(key)
  t.absent(client.drives.has(key))
  t.absent(client._driveForkListeners.has(key))
  t.is(removals, 2)
  await client.destroy()
})

test('client late ready-listener failure rolls back every upper owner before shared dependencies', async (t) => {
  const events = []
  const handle = { async destroy () { events.push('discovery') } }
  const swarm = new FakeSwarm(() => handle)
  const store = { external: true }
  const client = new HiveRelayClient({ store, swarm, autoDiscover: false })
  const connectionHandler = () => {}
  const key = '9'.repeat(64)
  const forkDetector = new EventEmitter()
  forkDetector.save = async () => { events.push('fork-save') }
  let pendingRejected = false
  const pending = new Promise((_resolve, reject) => {
    client._pendingServiceRequests.set('pending', {
      timer: setTimeout(() => {}, 60_000),
      reject: (err) => { pendingRejected = err.message === 'CLIENT_START_FAILED'; reject(err) }
    })
  }).catch(() => {})
  let releaseOperation = null
  const operationGate = new Promise(resolve => { releaseOperation = resolve })

  client._start = async () => {
    client._lifecycleAbort = new AbortController()
    client._started = true
    client._registry = { async stop () { events.push('registry') } }
    client._pairing = { async destroy () { events.push('pairing') } }
    client._connectionHandler = connectionHandler
    swarm.on('connection', connectionHandler)
    client._discoveryTopic = swarm.join(Buffer.alloc(32), { client: true })
    client._shareBundleCores.set('late-share', {
      discovery: null,
      core: { async close () { events.push('share-core') } }
    })
    client.drives.set(key, { async close () { events.push('drive') } })
    client.forkDetector = forkDetector
    client._replicationMonitors = new Map([['monitor', { stop () { events.push('monitor') } }]])
    client._pendingSeedTimers.set('seed', setTimeout(() => {}, 60_000))
    client._trackOperation(operationGate)
    client.emit('ready')
    return client
  }
  client.on('ready', () => { throw new Error('injected ready observer failure') })
  const starting = client.start()
  await new Promise(resolve => setTimeout(resolve, 0))
  releaseOperation()
  await t.exception(starting, /injected ready observer failure/)
  await pending

  t.alike(events, ['monitor', 'registry', 'pairing', 'discovery', 'share-core', 'drive', 'fork-save'])
  t.is(client._pendingSeedTimers.size, 0)
  t.is(client._operations.size, 0)
  t.is(client.drives.size, 0)
  t.is(client._shareBundleCores.size, 0)
  t.ok(pendingRejected)
  t.is(swarm.listenerCount('connection'), 0)
  t.is(client.store, store, 'shared Corestore remains caller-owned')
  t.is(client.swarm, swarm, 'shared swarm remains caller-owned')
  t.is(client._stopping, false)
  await client.destroy()
})

test('client ready-listener publish exposes provisional owner before failed-start rollback', async (t) => {
  const events = []
  let releaseDriveReady = null
  const driveReadyGate = new Promise(resolve => { releaseDriveReady = resolve })
  const key = Buffer.alloc(32, 10)
  const drive = {
    key,
    discoveryKey: Buffer.alloc(32, 11),
    async ready () {
      events.push('drive-ready-start')
      await driveReadyGate
      events.push('drive-ready-settled')
    },
    async put () { events.push('drive-put') },
    async close () { events.push('drive-close') }
  }
  const store = {
    namespace () { return this },
    async close () { events.push('store-close') }
  }
  const swarm = new FakeSwarm(() => ({
    async destroy () { events.push('discovery-destroy') }
  }))
  const client = new HiveRelayClient({ store, swarm, autoDiscover: false })
  // Exercise the owned-store ordering without constructing a real Corestore.
  client._ownsStore = true
  client._createPublishDrive = () => drive
  client._start = async () => {
    client._lifecycleAbort = new AbortController()
    client._started = true
    client.emit('ready')
    await new Promise(resolve => setImmediate(resolve))
    throw new Error('injected post-publish ready failure')
  }

  let publishing = null
  client.on('ready', () => {
    publishing = client.publish([{ path: '/index.html', content: 'hello' }], { seed: false })
  })

  const starting = client.start()
  await new Promise(resolve => setImmediate(resolve))
  t.is(client._operations.size, 1, 'real public publish is lifecycle tracked')
  t.is(client._provisionalPublishDrives.size, 1, 'tentative drive is owned before ready settles')
  t.absent(events.includes('store-close'), 'rollback cannot close Corestore beneath provisional drive')

  releaseDriveReady()
  await t.exception(starting, /injected post-publish ready failure/)
  await t.exception(publishing, /publish cancelled/)

  t.alike(events, ['drive-ready-start', 'drive-ready-settled', 'drive-close', 'store-close'])
  t.is(client._operations.size, 0)
  t.is(client._provisionalPublishDrives.size, 0)
  t.is(client.drives.size, 0, 'cancelled publish never becomes a live mapped drive')
  t.is(client.store, null, 'owned Corestore closes only after provisional drive settlement')
  t.is(client._stopping, false, 'successful rollback reopens lifecycle admission')
})

test('client failed published observer restores exact app mapping and launches no detached flush', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'hiverelay-client-publish-map-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const appId = 'mapped-app'
  const priorDiskKey = 'c'.repeat(64)
  const priorMemoryKey = 'd'.repeat(64)
  await writeFile(join(storage, 'app-drives.json'), JSON.stringify({ [appId]: priorDiskKey }))

  let flushes = 0
  let closes = 0
  const swarm = new FakeSwarm(() => ({ async destroy () {} }))
  swarm.flush = async () => { flushes++; await new Promise(() => {}) }
  const store = { namespace () { return this } }
  const client = new HiveRelayClient({ storage, store, swarm, autoDiscover: false })
  client._started = true
  client._lifecycleAbort = new AbortController()
  client._appDrives.set(appId, priorMemoryKey)
  const drive = {
    key: Buffer.alloc(32, 12),
    discoveryKey: Buffer.alloc(32, 13),
    async ready () {},
    async put () {},
    async close () { closes++ }
  }
  client._createPublishDrive = () => drive
  client.on('published', () => { throw new Error('injected published observer failure') })

  await t.exception(client.publish(
    [{ path: '/index.html', content: 'hello' }],
    { appId, key: 'e'.repeat(64), seed: false }
  ), /injected published observer failure/)

  const persisted = JSON.parse(await readFile(join(storage, 'app-drives.json'), 'utf8'))
  t.is(persisted[appId], priorDiskKey, 'disk mapping restores exact prior authority')
  t.is(client._appDrives.get(appId), priorMemoryKey, 'memory mapping restores exact prior authority')
  t.is(flushes, 0, 'publish does not launch an unowned Hyperswarm flush')
  t.is(closes, 1, 'failed committed publication closes the exact drive once')
  t.is(client.drives.size, 0)
  t.is(client._provisionalPublishDrives.size, 0)

  const autoAppId = 'auto-app'
  const autoDiskKey = 'f'.repeat(64)
  const autoMemoryKey = '0'.repeat(64)
  await client._saveAppDriveMapping(autoAppId, autoDiskKey, { throwOnError: true })
  client._appDrives.set(autoAppId, autoMemoryKey)
  let autoCloses = 0
  const autoDrive = {
    key: Buffer.alloc(32, 16),
    discoveryKey: Buffer.alloc(32, 17),
    async ready () {},
    async put () {},
    async close () { autoCloses++ }
  }
  client._createPublishDrive = () => autoDrive
  client._readDirectory = async () => [{ path: '/index.html', content: 'auto' }]
  await t.exception(
    client.publish('/virtual/auto-app', { key: 'a'.repeat(64), seed: false }),
    /injected published observer failure/
  )
  const autoPersisted = JSON.parse(await readFile(join(storage, 'app-drives.json'), 'utf8'))
  t.is(autoPersisted[autoAppId], autoDiskKey, 'auto-derived appId restores prior disk mapping')
  t.is(client._appDrives.get(autoAppId), autoMemoryKey, 'auto-derived appId restores prior memory mapping')
  t.is(autoCloses, 1)
  await client.destroy()
})

test('client failed publish lane cannot clobber a newer same-app same-key commit', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'hiverelay-client-publish-cas-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const appId = 'concurrent-app'
  const priorKey = '1'.repeat(64)
  await writeFile(join(storage, 'app-drives.json'), JSON.stringify({ [appId]: priorKey }))

  const swarm = new FakeSwarm(() => ({ async destroy () {} }))
  const store = { namespace () { return this } }
  const client = new HiveRelayClient({ storage, store, swarm, autoDiscover: false })
  client._started = true
  client._lifecycleAbort = new AbortController()
  client._appDrives.set(appId, priorKey)
  const sharedKey = Buffer.alloc(32, 14)
  const closes = []
  const drives = [0, 1].map(index => ({
    key: sharedKey,
    discoveryKey: Buffer.alloc(32, 20 + index),
    async ready () {},
    async put () {},
    async close () { closes.push(index) }
  }))
  let created = 0
  client._createPublishDrive = () => drives[created++]
  const sharedKeyHex = sharedKey.toString('hex')
  let published = 0
  client.on('published', () => {
    if (++published === 1) throw new Error('injected first publish observer failure')
  })

  const results = await Promise.allSettled([
    client.publish([{ path: '/a', content: 'a' }], { appId, key: '2'.repeat(64), seed: false }),
    client.publish([{ path: '/b', content: 'b' }], { appId, key: '3'.repeat(64), seed: false })
  ])

  t.is(results[0].status, 'rejected')
  t.is(results[1].status, 'fulfilled')
  const persisted = JSON.parse(await readFile(join(storage, 'app-drives.json'), 'utf8'))
  t.is(persisted[appId], sharedKeyHex, 'failed older restore does not overwrite newer same-key disk commit')
  t.is(client._appDrives.get(appId), sharedKeyHex, 'failed older restore does not overwrite newer same-key memory commit')
  t.alike(closes, [0], 'only failed publication is retired before destroy')
  await client.destroy()
  t.alike(closes, [0, 1], 'newer successful publication remains owned until destroy')
})

test('client successful mixed-identity same-key publishes reuse one live drive owner', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const sharedKey = Buffer.alloc(32, 21)
  let creates = 0
  let closes = 0
  const drive = {
    key: sharedKey,
    discoveryKey: Buffer.alloc(32, 22),
    async ready () {},
    async put () {},
    async close () { closes++ }
  }
  client._createPublishDrive = () => { creates++; return drive }
  const files = [{ path: '/index.html', content: 'hello' }]

  const first = await client.publish(files, { appId: 'first-app', key: sharedKey, seed: false })
  const second = await client.publish(files, { appId: 'second-app', key: sharedKey, seed: false })
  t.is(first, drive)
  t.is(second, drive, 'second identity borrows the already-live exact drive')
  t.is(creates, 1, 'same drive key creates only one Hyperdrive owner')
  t.is(client.drives.get(sharedKey.toString('hex')), drive)

  await client.destroy()
  t.is(closes, 1, 'destroy settles the reused exact drive once')
})

test('client publish waits same-key open and borrows its exact owner', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 26)
  const keyHex = key.toString('hex')
  let releaseOpen = null
  const openGate = new Promise(resolve => { releaseOpen = resolve })
  let publishCreates = 0
  let closes = 0
  const drive = {
    key,
    discoveryKey: Buffer.alloc(32, 27),
    async ready () {},
    async put () {},
    async close () { closes++ }
  }
  client._open = async () => {
    await openGate
    client.drives.set(keyHex, drive)
    return drive
  }
  client._createPublishDrive = () => { publishCreates++; return drive }

  const opening = client.open(key, { wait: false })
  const publishing = client.publish([{ path: '/index.html', content: 'hello' }], {
    key,
    seed: false
  })
  await new Promise(resolve => setImmediate(resolve))
  t.is(publishCreates, 0, 'publish cannot create a competing owner while open is pending')
  releaseOpen()
  const [opened, published] = await Promise.all([opening, publishing])
  t.is(opened, drive)
  t.is(published, drive, 'publish borrows owner installed by open')
  t.is(publishCreates, 0)
  await client.destroy()
  t.is(closes, 1)
})

test('client close is ordered between active and later same-key publishes', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  const key = Buffer.alloc(32, 28)
  const events = []
  let releaseFirstPut = null
  const firstPutGate = new Promise(resolve => { releaseFirstPut = resolve })
  const firstDrive = {
    key,
    discoveryKey: Buffer.alloc(32, 29),
    async ready () {},
    async put () {
      events.push('first-put-start')
      await firstPutGate
      events.push('first-put-end')
    },
    async close () { events.push('first-close') }
  }
  const secondDrive = {
    key,
    discoveryKey: Buffer.alloc(32, 30),
    async ready () {},
    async put () { events.push('second-put') },
    async close () { events.push('second-close') }
  }
  const drives = [firstDrive, secondDrive]
  client._createPublishDrive = () => drives.shift()
  const files = [{ path: '/index.html', content: 'hello' }]

  const first = client.publish(files, { key, seed: false })
  await new Promise(resolve => setImmediate(resolve))
  const closing = client.closeDrive(key)
  const second = client.publish(files, { key, seed: false })
  const closingAgain = client.closeDrive(key)
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events, ['first-put-start'], 'close and later publish stay queued behind active publish')
  releaseFirstPut()
  await Promise.all([first, closing, second, closingAgain])
  t.alike(events, ['first-put-start', 'first-put-end', 'first-close', 'second-put', 'second-close'])
  t.absent(client.drives.has(key.toString('hex')), 'trailing close runs after and retires later publish')
  await client.destroy()
  t.alike(events, ['first-put-start', 'first-put-end', 'first-close', 'second-put', 'second-close'])
})

test('client seed observer failure removes rebroadcast listener', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  client.keyPair = hypercoreCrypto.keyPair()
  client.on('seed-request-published', () => { throw new Error('injected seed observer failure') })
  await t.exception(client.seed(Buffer.alloc(32, 23), {
    maxStorage: 1024,
    replicas: 1,
    timeout: 1,
    retryPersistent: false
  }), /injected seed observer failure/)
  t.is(client.listenerCount('relay-connected'), 0, 'throwing observer leaves no stale rebroadcast listener')
  await client.destroy()
})

test('client same-key seed lane publishes distinct requests sequentially', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  client.keyPair = hypercoreCrypto.keyPair()
  let calls = 0
  let releaseFirst = null
  const firstGate = new Promise(resolve => { releaseFirst = resolve })
  client._registry = {
    async publishRequest () {
      calls++
      if (calls === 1) await firstGate
    },
    async stop () {}
  }
  const key = Buffer.alloc(32, 24)
  const first = client.seed(key, { maxStorage: 1024, replicas: 1, timeout: 1, retryPersistent: false })
  const second = client.seed(key, { maxStorage: 2048, replicas: 2, timeout: 1, retryPersistent: false })
  await new Promise(resolve => setImmediate(resolve))
  t.is(calls, 1, 'second same-key seed cannot overwrite the active request')
  releaseFirst()
  await Promise.all([first, second])
  t.is(calls, 2, 'both distinct registry requests publish exactly once')
  t.is(client.seedRequests.get(key.toString('hex')).target, 2, 'last request becomes current only after first settles')
  await client.destroy()
})

test('client retained registry timeout cannot deduplicate a later same-key seed', async (t) => {
  const client = readerHarness(() => ({ async destroy () {} }))
  client.keyPair = hypercoreCrypto.keyPair()
  let calls = 0
  let releaseFirst = null
  const firstGate = new Promise(resolve => { releaseFirst = resolve })
  client._registry = {
    async publishRequest () {
      calls++
      if (calls === 1) await firstGate
    },
    async stop () {}
  }
  const key = Buffer.alloc(32, 25)
  await client.seed(key, {
    maxStorage: 1024,
    replicas: 1,
    registryTimeout: 1,
    timeout: 1,
    retryPersistent: false
  })
  await client.seed(key, {
    maxStorage: 2048,
    replicas: 2,
    registryTimeout: 1,
    timeout: 1,
    retryPersistent: false
  })
  t.is(calls, 1, 'second distinct request remains retained behind timed-out first publish')
  releaseFirst()
  await new Promise(resolve => setImmediate(resolve))
  await new Promise(resolve => setImmediate(resolve))
  t.is(calls, 2, 'unique exact-owner label eventually publishes the later request')
  await client.destroy()
})
