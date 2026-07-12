import test from 'brittle'
import http from 'http'
import { Readable } from 'stream'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { issueExactAppContext } from '../../packages/core/gateway/exact-app-context.js'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'

const KEY = 'a'.repeat(64)
const PUBLIC = {
  blind: false,
  privacyTier: 'public',
  storageClass: 'persistent',
  availabilityClass: 'always-on'
}

test('HyperGateway runtime - cache and operation bounds fail closed', (t) => {
  t.exception(() => new HyperGateway({}, { maxCachedDrives: 0 }), /maxCachedDrives must be an integer/)
  t.exception(() => new HyperGateway({}, { maxCachedDrives: 257 }), /maxCachedDrives must be an integer/)
  t.exception(() => new HyperGateway({}, { driveOperationTimeout: '30000' }), /driveOperationTimeout must be an integer/)
  t.exception(() => new HyperGateway({}, { driveOperationTimeout: 120001 }), /driveOperationTimeout must be an integer/)
  t.exception(() => new HyperGateway({}, { requireLifecycleDriveAuthority: 'yes' }), /must be boolean/)
})

test('HyperGateway runtime - exact responses use one immutable checkout', async (t) => {
  const original = Buffer.from('version-seven\n')
  const changed = Buffer.from('version-eight-is-longer\n')
  let parentReads = 0
  let checkoutCalls = 0
  let checkoutCloseCalls = 0

  const snapshot = fileDrive(original)
  snapshot.version = 7
  snapshot.close = async () => { snapshot.closed = true; checkoutCloseCalls++ }

  const parent = fileDrive(changed)
  parent.version = 7
  parent.update = async () => true
  parent.entry = async () => { parentReads++; return { value: { blob: { byteLength: changed.length } } } }
  parent.checkout = (version) => {
    checkoutCalls++
    if (version !== 7) throw new Error('wrong snapshot version')
    parent.version = 8
    return snapshot
  }

  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive: parent, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, {})
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/index.html',
    byteMode: 'exact',
    publicAppKeys: [KEY]
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const res = await request(server.address().port, '/')
  t.is(res.statusCode, 200)
  t.is(res.headers['x-hive-drive-version'], '7')
  t.is(res.headers['content-length'], String(original.length), 'length comes from the frozen version')
  t.ok(res.raw.equals(original), 'body comes from the same frozen version')
  t.is(checkoutCalls, 1, 'one checkout created per exact request')
  t.is(parentReads, 0, 'mutable parent head is never read after checkout')
  await immediate()
  t.is(checkoutCloseCalls, 1, 'request checkout closes after response completion')
})

test('HyperGateway runtime - configured version pin survives a newer publisher head', async (t) => {
  const approved = Buffer.from('approved-version-seven\n')
  const latest = Buffer.from('unapproved-version-eight\n')
  let checkoutVersion = null
  const snapshot = fileDrive(approved)
  snapshot.version = 7
  snapshot.close = async () => { snapshot.closed = true }
  const parent = fileDrive(latest)
  parent.version = 8
  parent.checkout = version => {
    checkoutVersion = version
    return snapshot
  }

  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive: parent, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, {})
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/index.html',
    byteMode: 'exact',
    publicAppKeys: [KEY],
    driveVersion: 7
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const res = await request(server.address().port, '/')
  t.is(res.statusCode, 200)
  t.is(checkoutVersion, 7, 'runtime uses the signed/configured immutable version')
  t.is(res.headers['x-hive-drive-version'], '7')
  t.ok(res.raw.equals(approved), 'newer publisher head cannot change the approved browser origin')
})

test('HyperGateway runtime - exact drive update timeout cancels replicator requests', async (t) => {
  const body = Buffer.from('never-reached\n')
  let activeRequests = null
  let clearCalls = 0
  const drive = fileDrive(body)
  drive.update = ({ activeRequests: requests }) => {
    activeRequests = requests
    requests.push({ pending: true })
    return new Promise(() => {})
  }
  drive.db = {
    core: {
      replicator: {
        clearRequests (requests) {
          clearCalls++
          requests.splice(0)
        }
      }
    }
  }
  drive.checkout = () => {
    t.fail('timed-out mutable drive must never create a checkout')
  }

  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, { driveOperationTimeout: 20 })
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/index.html',
    byteMode: 'exact',
    publicAppKeys: [KEY]
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const res = await request(server.address().port, '/')
  t.is(res.statusCode, 502)
  t.is(res.headers['x-hive-byte-mode'], 'generated')
  t.ok(activeRequests, 'gateway supplied an explicit cancellable request set')
  t.is(activeRequests.length, 0, 'timeout detaches every pending upgrade request')
  t.ok(clearCalls >= 1, 'replicator cancellation runs on timeout')
})

test('HyperGateway runtime - shutdown aborts an exact update and drains request state', async (t) => {
  const body = Buffer.from('never-streamed')
  let activeRequests = null
  let clearCalls = 0
  let closeCalls = 0
  let notifyUpdateStarted
  const updateStarted = new Promise(resolve => { notifyUpdateStarted = resolve })
  const drive = fileDrive(body)
  drive.checkout = () => fileDrive(body)
  drive.update = ({ activeRequests: requests }) => {
    activeRequests = requests
    requests.push({ operation: 'exact-update' })
    notifyUpdateStarted()
    return new Promise(() => {})
  }
  drive.db = {
    core: {
      replicator: {
        clearRequests (requests) {
          clearCalls++
          requests.splice(0)
        }
      }
    }
  }
  drive.close = async () => { closeCalls++ }
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, { driveOperationTimeout: 1000 })
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/index.html',
    byteMode: 'exact',
    publicAppKeys: [KEY]
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const client = http.get({ hostname: '127.0.0.1', port: server.address().port, path: '/', agent: false })
  client.on('error', () => {})
  client.on('response', res => res.resume())
  await updateStarted
  await gateway.close()
  await immediate()

  t.ok(activeRequests, 'exact update registered an operation request set')
  t.is(activeRequests.length, 0, 'shutdown detaches the exact update refs immediately')
  t.is(clearCalls, 1, 'shutdown cancellation is idempotent')
  t.is(closeCalls, 0, 'gateway shutdown never closes the borrowed seeded parent')
  t.is(gateway._activeRequestStates.size, 0, 'request state is fully drained')
  t.is(gateway._pendingRequestCleanups.size, 0, 'request lease cleanup is fully drained')
  client.destroy()
})

test('HyperGateway runtime - hot cached drive refreshes are singleflight and cancellable', async (t) => {
  let updateCalls = 0
  let clearCalls = 0
  const drive = closableDrive()
  drive.update = ({ activeRequests }) => {
    updateCalls++
    activeRequests.push({ operation: 'refresh' })
    return new Promise(() => {})
  }
  drive.db = {
    core: {
      replicator: {
        clearRequests (requests) {
          clearCalls++
          requests.splice(0)
        }
      }
    }
  }
  const gateway = new HyperGateway({ seededApps: new Map() }, { driveOperationTimeout: 1000 })
  gateway._drives.set(KEY, drive)

  const leases = await Promise.all(Array.from({ length: 100 }, () => gateway._acquireDrive(KEY)))
  for (const lease of leases) lease.release()
  t.is(updateCalls, 1, 'one hundred cache hits create one refresh operation')
  t.is(gateway._driveRefreshPromises.size, 1)

  await gateway.close()
  t.is(clearCalls, 1, 'shutdown cancels the one refresh request set')
  t.is(gateway._driveRefreshPromises.size, 0)
  t.is(drive.closeCalls, 1, 'owned cached session closes once after refresh drains')
})

test('HyperGateway runtime - owned swarm topics leave only after the final session closes', async (t) => {
  const topic = Buffer.alloc(32, 4)
  const leaves = []
  const gateway = new HyperGateway({}, { driveOperationTimeout: 1000 })
  gateway._swarm = {
    async leave (discoveryKey) { leaves.push(Buffer.from(discoveryKey).toString('hex')) }
  }
  const first = closableDrive()
  const second = closableDrive()
  gateway._trackOwnedDriveTopic(first, topic)
  gateway._trackOwnedDriveTopic(second, topic)

  await gateway._closeOwnedDrive(first)
  t.is(leaves.length, 0, 'shared discovery topic remains while another session owns it')
  await gateway._closeOwnedDrive(second)
  t.alike(leaves, [topic.toString('hex')], 'final close leaves the topic exactly once')
  t.is(gateway._ownedDriveTopics.size, 0)
  t.is(gateway._ownedTopicRefs.size, 0)
})

test('HyperGateway runtime - concurrent exact range and HEAD requests release every checkout', async (t) => {
  const body = Buffer.from('0123456789abcdef')
  let checkoutCalls = 0
  let checkoutCloseCalls = 0
  let updateCalls = 0
  let releaseUpdate
  const updateGate = new Promise(resolve => { releaseUpdate = resolve })
  const parent = fileDrive(body)
  parent.version = 0
  parent.update = async () => {
    updateCalls++
    await updateGate
    parent.version = 1
  }
  parent.checkout = () => {
    checkoutCalls++
    const snapshot = fileDrive(body)
    snapshot.close = async () => { snapshot.closed = true; checkoutCloseCalls++ }
    return snapshot
  }
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive: parent, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, { maxResponseBytes: 16 })
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/asset.bin',
    byteMode: 'exact',
    publicAppKeys: [KEY],
    driveVersion: 1
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const pendingResponses = Promise.all(Array.from({ length: 40 }, (_, i) => {
    return request(server.address().port, '/', i % 2 === 0
      ? { headers: { Range: 'bytes=2-9' } }
      : { method: 'HEAD' })
  }))
  for (let i = 0; i < 100; i++) {
    if (gateway._seededDriveUpdateStates.get(KEY)?.waiters === 40) break
    await new Promise(resolve => setTimeout(resolve, 1))
  }
  t.is(gateway._seededDriveUpdateStates.get(KEY)?.waiters, 40, 'all readers joined the same pending update')
  releaseUpdate()
  const responses = await pendingResponses
  for (let i = 0; i < responses.length; i++) {
    t.is(responses[i].statusCode, i % 2 === 0 ? 206 : 200)
    t.is(responses[i].raw.length, i % 2 === 0 ? 8 : 0)
  }
  await immediate()
  t.is(updateCalls, 1, 'concurrent exact readers share one mutable-head update')
  t.is(checkoutCalls, 40)
  t.is(checkoutCloseCalls, 40, 'every concurrent immutable checkout closed')
  t.is(gateway._activeRequestStates.size, 0)
  t.is(gateway._pendingRequestCleanups.size, 0)
})

test('HyperGateway runtime - aborted slow readers destroy streams and release all leases', async (t) => {
  const registry = new AppRegistry(null)
  let streamDestroyCalls = 0
  let checkoutCloseCalls = 0
  let parentCloseCalls = 0
  const parent = fileDrive(Buffer.alloc(1024))
  parent.discoveryKey = Buffer.alloc(32, 9)
  parent.checkout = () => ({
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async entry () { return { value: { blob: { byteLength: 1024 } } } },
    createReadStream () {
      let sent = false
      return new Readable({
        read () {
          if (sent) return
          sent = true
          this.push(Buffer.alloc(1, 7))
        },
        destroy (err, callback) {
          streamDestroyCalls++
          callback(err)
        }
      })
    },
    async close () { this.closed = true; checkoutCloseCalls++ },
    async * list () {}
  })
  parent.close = async () => { parent.closed = true; parentCloseCalls++ }
  registry.set(KEY, {
    drive: parent,
    discoveryKey: parent.discoveryKey,
    type: 'app',
    ...PUBLIC
  }, { persist: false })
  const node = {
    appRegistry: registry,
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: registry.apps,
    swarm: { leave: async () => {} }
  }
  node.appLifecycle = new AppLifecycle(node)
  const gateway = new HyperGateway(node, {})
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/large.bin',
    byteMode: 'exact',
    publicAppKeys: [KEY],
    driveVersion: 1
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  await Promise.all(Array.from({ length: 25 }, () => abortAfterFirstByte(server.address().port)))
  for (let i = 0; i < 100; i++) {
    if (checkoutCloseCalls === 25 && gateway._activeRequestStates.size === 0) break
    await new Promise(resolve => setTimeout(resolve, 1))
  }

  t.is(streamDestroyCalls, 25, 'every disconnected slow reader destroys its Hyperdrive stream')
  t.is(checkoutCloseCalls, 25, 'every aborted response closes its immutable checkout')
  t.is(parentCloseCalls, 0, 'aborts never close the shared seeded parent')
  t.is(node.appLifecycle._driveReadLeaseStates.size, 0, 'AppLifecycle retains no reader lease state')
  t.is(gateway._activeRequestStates.size, 0)
  t.is(gateway._pendingRequestCleanups.size, 0)
})

test('HyperGateway runtime - borrowed seeded drives never enter or close through the LRU', async (t) => {
  const seededApps = new Map()
  const drives = []
  for (let i = 0; i < 25; i++) {
    const drive = closableDrive()
    const key = i.toString(16).padStart(64, '0')
    drives.push(drive)
    seededApps.set(key, { drive, ...PUBLIC })
  }
  const gateway = new HyperGateway({ seededApps }, { maxCachedDrives: 1 })

  for (const key of seededApps.keys()) {
    const lease = await gateway._acquireDrive(key)
    lease.release()
  }
  t.is(gateway._drives.size, 0, 'borrowed AppLifecycle drives are not cached as gateway-owned')

  await gateway.close()
  t.ok(drives.every(drive => drive.closeCalls === 0), 'gateway shutdown does not close borrowed seeded drives')
})

test('HyperGateway runtime - unseed drains an active borrowed exact-response lease before closing its parent drive', async (t) => {
  const body = Buffer.from('borrowed-drive-stays-readable\n')
  const registry = new AppRegistry(null)
  let parentCloseCalls = 0
  let checkoutCloseCalls = 0
  let activeStream = null
  let notifyStreamStarted
  const streamStarted = new Promise(resolve => { notifyStreamStarted = resolve })

  const checkout = fileDrive(body)
  checkout.close = async () => {
    checkoutCloseCalls++
    checkout.closed = true
  }
  checkout.createReadStream = () => {
    activeStream = new Readable({ read () {} })
    notifyStreamStarted()
    return activeStream
  }

  const parent = fileDrive(body)
  parent.discoveryKey = Buffer.alloc(32, 7)
  parent.checkout = () => checkout
  parent.close = async () => {
    parentCloseCalls++
    parent.closed = true
    if (activeStream && !activeStream.readableEnded && !activeStream.destroyed) {
      const err = Object.assign(new Error('Cannot make sessions on a closing core'), {
        code: 'SESSION_CLOSED'
      })
      activeStream.destroy(err)
    }
  }

  registry.set(KEY, {
    drive: parent,
    discoveryKey: parent.discoveryKey,
    type: 'app',
    ...PUBLIC
  }, { persist: false })
  registry.persistDelete = async () => {}

  const node = {
    appRegistry: registry,
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: registry.apps,
    swarm: { leave: async () => {} }
  }
  node.appLifecycle = new AppLifecycle(node)

  const gateway = new HyperGateway(node, {})
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/index.html',
    byteMode: 'exact',
    publicAppKeys: [KEY]
  })))
  await listen(server)
  t.teardown(async () => {
    if (activeStream && !activeStream.readableEnded) activeStream.push(null)
    await closeServer(server)
    await gateway.close()
  })

  const pendingResponse = request(server.address().port, '/')
  await streamStarted

  let unseedSettled = false
  const pendingUnseed = node.appLifecycle.unseedApp(KEY).then(() => { unseedSettled = true })
  await immediate()

  t.absent(registry.has(KEY), 'unseed removes public admission before waiting')
  t.absent(unseedSettled, 'unseed waits for the active response lease')
  t.is(parentCloseCalls, 0, 'AppLifecycle cannot close the borrowed parent mid-response')

  activeStream.push(body)
  activeStream.push(null)
  const res = await pendingResponse
  await pendingUnseed

  t.is(res.statusCode, 200)
  t.ok(res.raw.equals(body), 'the exact response completes without SESSION_CLOSED truncation')
  t.is(checkoutCloseCalls, 1, 'immutable request checkout closes before lease release')
  t.is(parentCloseCalls, 1, 'AppLifecycle closes its parent after the response drains')
})

test('HyperGateway runtime - active owned drive is closed only after eviction lease releases', async (t) => {
  const gateway = new HyperGateway({}, { maxCachedDrives: 1 })
  const first = closableDrive()
  const second = closableDrive()
  gateway._drives.set('first', first)
  const lease = gateway._leaseOwnedDrive(first)

  gateway._drives.set('second', second)
  await immediate()
  t.is(first.closeCalls, 0, 'LRU eviction cannot close an actively used drive')

  lease.release()
  await immediate()
  t.is(first.closeCalls, 1, 'retired drive closes after the active response releases it')

  await gateway.close()
  t.is(second.closeCalls, 1, 'remaining gateway-owned drive closes at shutdown')
})

test('HyperGateway runtime - concurrent per-key misses share one open', async (t) => {
  const gateway = new HyperGateway({ seededApps: new Map() }, { maxCachedDrives: 2 })
  const drive = closableDrive()
  let opens = 0
  let releaseOpen
  const gate = new Promise(resolve => { releaseOpen = resolve })
  gateway._openDrive = async (key) => {
    opens++
    await gate
    gateway._drives.set(key, drive)
    return drive
  }

  const pending = Array.from({ length: 20 }, () => gateway._acquireDrive(KEY))
  releaseOpen()
  const leases = await Promise.all(pending)
  t.is(opens, 1, 'twenty concurrent misses create one drive session')
  for (const lease of leases) lease.release()
  await gateway.close()
  t.is(drive.closeCalls, 1)
})

test('HyperGateway runtime - the final aborted waiter cancels a shared drive open', async (t) => {
  const gateway = new HyperGateway({ seededApps: new Map() }, { driveOperationTimeout: 1000 })
  let internalSignal = null
  gateway._openDrive = async (key, signal) => {
    internalSignal = signal
    return new Promise(resolve => {
      signal.addEventListener('abort', () => resolve(null), { once: true })
    })
  }
  const client = new AbortController()
  const pending = gateway._acquireDrive(KEY, { signal: client.signal })
  await immediate()
  client.abort()

  let failure = null
  try { await pending } catch (err) { failure = err }
  await immediate()
  t.is(failure?.name, 'AbortError')
  t.ok(internalSignal?.aborted, 'no-reader open is cancelled instead of running to timeout')
  t.is(gateway._driveOpenStates.size, 0)
  t.is(gateway._driveOpenPromises.size, 0)
  await gateway.close()
})

test('HyperGateway runtime - concurrent drive opens share one store initialization', async (t) => {
  let readyCalls = 0
  let closeCalls = 0
  let releaseReady
  const readyGate = new Promise(resolve => { releaseReady = resolve })
  const store = {
    async ready () {
      readyCalls++
      await readyGate
    },
    async close () { closeCalls++ }
  }
  const gateway = new HyperGateway({}, { store })

  const pending = Array.from({ length: 20 }, () => gateway._ensureReady())
  await immediate()
  t.is(readyCalls, 1, 'twenty callers initialize the shared Corestore once')
  releaseReady()
  await Promise.all(pending)
  t.ok(gateway._ready)
  await gateway.close()
  t.is(closeCalls, 0, 'gateway shutdown never closes a borrowed RelayNode Corestore')
  t.absent(gateway._ready, 'gateway lifecycle state resets after shutdown')
  await gateway._ensureReady()
  t.is(readyCalls, 2, 'a restarted gateway reuses and readies the borrowed store')
  await gateway.close()
  t.is(closeCalls, 0)
})

test('HyperGateway runtime - failed shared-store initialization can retry without taking ownership', async (t) => {
  let attempts = 0
  let closeCalls = 0
  const store = {
    async ready () {
      attempts++
      if (attempts === 1) throw new Error('temporary store failure')
    },
    async close () { closeCalls++ }
  }
  const gateway = new HyperGateway({}, { store })
  let failure = null
  try { await gateway._ensureReady() } catch (err) { failure = err }

  t.is(failure?.message, 'temporary store failure')
  t.absent(gateway._ready)
  t.is(gateway._store, null, 'failed initialization does not retain partial state')
  await gateway._ensureReady()
  t.ok(gateway._ready, 'next initialization attempt succeeds')
  t.is(attempts, 2)
  await gateway.close()
  t.is(closeCalls, 0, 'borrowed store remains caller-owned after failure and recovery')
})

test('HyperGateway runtime - a stalled directory iterator returns a bounded generic failure', async (t) => {
  let returnCalls = 0
  const drive = fileDrive(Buffer.from('unused'))
  drive.checkout = () => drive
  drive.entry = async () => null
  drive.list = () => ({
    [Symbol.asyncIterator] () { return this },
    next () { return new Promise(() => {}) },
    async return () { returnCalls++; return { done: true } }
  })
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, ...PUBLIC }]])
  }
  const gateway = new HyperGateway(node, { driveOperationTimeout: 20 })
  const errors = []
  gateway.on('drive-error', event => errors.push(event))
  const server = http.createServer((req, res) => gateway.handle(req, res, issueExactAppContext({
    appKey: KEY,
    path: '/',
    byteMode: 'exact',
    publicAppKeys: [KEY]
  })))
  await listen(server)
  t.teardown(async () => {
    await closeServer(server)
    await gateway.close()
  })

  const res = await request(server.address().port, '/')
  t.is(res.statusCode, 502)
  t.is(JSON.parse(res.raw.toString()).error, 'Gateway directory listing failed')
  t.is(res.headers['cache-control'], 'no-store, max-age=0')
  t.is(res.headers['x-hive-byte-mode'], 'generated')
  t.is(returnCalls, 1, 'timed-out iterator is explicitly closed')
  t.is(errors.length, 1)
})

function fileDrive (data) {
  return {
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async update () {},
    async entry () { return { value: { blob: { byteLength: data.length } } } },
    createReadStream (path, opts = {}) {
      const start = opts.start || 0
      const end = opts.length == null ? data.length : start + opts.length
      return Readable.from([data.subarray(start, end)])
    },
    async * list () {}
  }
}

function closableDrive () {
  return {
    closed: false,
    closing: false,
    closeCalls: 0,
    async close () { this.closeCalls++; this.closed = true }
  }
}

function listen (server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
}

function closeServer (server) {
  if (!server.listening) return Promise.resolve()
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
  return new Promise(resolve => server.close(resolve))
}

function request (port, path, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      agent: false,
      method: opts.method || 'GET',
      headers: opts.headers || {}
    }, res => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        raw: Buffer.concat(chunks)
      }))
    })
    req.on('error', reject)
    req.end()
  })
}

function immediate () {
  return new Promise(resolve => setImmediate(resolve))
}

function abortAfterFirstByte (port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path: '/', agent: false }, res => {
      res.once('data', () => {
        req.destroy()
        resolve()
      })
      res.on('error', () => {})
    })
    req.on('error', err => {
      if (err.code === 'ECONNRESET') resolve()
      else reject(err)
    })
  })
}
