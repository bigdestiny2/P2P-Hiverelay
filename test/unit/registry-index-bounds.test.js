import test from 'brittle'
import { EventEmitter } from 'events'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'
import { LifecycleScope } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'
import { createCustodyIntent } from 'p2p-hiverelay/core/custody-signing.js'

const turn = () => new Promise(resolve => setImmediate(resolve))
const hex = n => n.toString(16).padStart(64, '0')
function gate () {
  let resolve
  const promise = new Promise(_resolve => { resolve = _resolve })
  return { promise, resolve }
}

class Log extends EventEmitter {
  constructor (n = 1) {
    super()
    this.key = b4a.from(hex(n), 'hex')
    this.blocks = []
    this.reads = 0
    this.closed = false
    this.readGate = null
    this.appendGate = null
    this.readyGate = null
  }

  get length () { return this.blocks.length }
  async ready () { if (this.readyGate) await this.readyGate.promise }
  replicate () {}
  async get (i) {
    this.reads++
    if (this.readGate) await this.readGate.promise
    if (this.closed) throw new Error('read after close')
    return this.blocks[i]
  }

  async append (block) {
    if (this.appendGate) await this.appendGate.promise
    if (this.closed) throw new Error('append after close')
    this.blocks.push(block)
    this.emit('append')
  }

  async close () { this.closed = true }
}

function acceptance (n) {
  return { type: 'seed-accept', timestamp: Date.now(), appKey: hex(n), relayPubkey: hex(7), region: 'eu' }
}

async function setup () {
  const log = new Log()
  const swarm = new EventEmitter()
  swarm.join = () => ({ async destroy () {} })
  const scope = new LifecycleScope()
  const registry = new SeedingRegistry({ get: opts => opts.name === 'seeding-registry-local' ? log : null }, swarm, { scope })
  await registry.start()
  const writes = new Map()
  const putGate = gate()
  let active = 0
  let peak = 0
  let calls = 0
  registry._indexBeeReady = true
  registry._indexBee = {
    async put (key, entry) {
      calls++
      active++
      peak = Math.max(peak, active)
      await putGate.promise
      if (log.closed) throw new Error('write after close')
      writes.set(key, entry)
      active--
    }
  }
  return { registry, log, scope, writes, putGate, stats: () => ({ active, peak, calls }) }
}

test('registry append burst owns one reader and bounded writes without losing accepted blocks', async t => {
  const { registry, log, scope, writes, putGate, stats } = await setup()
  const readGate = gate()
  log.readGate = readGate
  for (let i = 1; i <= 2048; i++) log.append(b4a.from(JSON.stringify(acceptance(i))))
  await turn()
  t.is(log.reads, 1, '2048 notifications retain one blocked log.get')
  t.is(registry._indexFlights.size, 1)
  t.is(scope._inflight.size, 1, 'scope retains one owner, not 2048 observer wrappers')
  readGate.resolve()
  await turn()
  t.is(stats().active, 64, 'slow Bee admits at most 64 writes')
  t.is(log.reads, 65, 'reader retains at most the next block under backpressure')
  t.is(registry._indexedOffsets.get(hex(1)), 64, 'blocked block offset is not skipped')
  t.is(registry._pendingIndexOps.size, 64)
  for (let i = 0; i < 2048; i++) log.emit('append')
  await turn()
  t.is(log.reads, 65, 'repeated notifications cannot bypass write pressure')
  t.is(scope._inflight.size, 1)
  putGate.resolve()
  await registry._indexFlights.get(hex(1))
  await registry._flushIndexBee()
  t.is(log.reads, 2048, 'each authoritative block read once')
  t.is(stats().calls, 2048, 'each accepted entry written once')
  t.is(stats().peak, 64)
  t.is(writes.size, 2048, 'all distinct accepted records persisted')
  t.is(registry._acceptances.size, 2048, 'all records applied')
  t.is(registry._indexedOffsets.get(hex(1)), 2048)
  t.is(registry._indexFlights.size, 0)
  await registry.stop()
})

test('registry stop drains a blocked read then its cache write before closing the log', async t => {
  const { registry, log, putGate, writes } = await setup()
  log.readGate = gate()
  await log.append(b4a.from(JSON.stringify(acceptance(1))))
  const stopped = registry.stop()
  await turn()
  t.absent(log.closed, 'log is open while read is owned')
  t.is(registry._indexFlights.size, 1)
  log.readGate.resolve()
  await turn()
  t.is(registry._pendingIndexOps.size, 1, 'read has transferred ownership to cache write')
  t.absent(log.closed, 'log remains open until write settles')
  putGate.resolve()
  await stopped
  t.ok(log.closed)
  t.is(writes.size, 1, 'accepted block retained through shutdown')
  t.is(registry._indexFlights.size, 0)
  t.is(registry._pendingIndexOps.size, 0)
})

test('registry local mutation burst rejects before append and drains every admitted mutation', async t => {
  const { registry, log, putGate, writes, stats } = await setup()
  log.appendGate = gate()
  const results = []
  for (let i = 1; i <= 2048; i++) {
    results.push(registry.recordAcceptance(hex(i), hex(7), 'eu').then(() => 'accepted', err => err.code))
  }
  await turn()
  t.is(registry._pendingMutations, 256, 'mutation owners and waiters have a hard admission cap')
  t.is(log.length, 0, 'admission precedes the authoritative append')
  log.appendGate.resolve()
  await turn()
  t.is(log.length, 256, 'only admitted operations appended')
  t.is(stats().active, 64, 'different-key mutation burst cannot bypass write cap')
  const stopped = registry.stop()
  await turn()
  t.absent(log.closed)
  t.is(await registry.recordAcceptance(hex(3000), hex(7), 'eu').catch(err => err.code), 'REGISTRY_STOPPING')
  putGate.resolve()
  const outcomes = await Promise.all(results)
  await stopped
  t.is(outcomes.filter(result => result === 'accepted').length, 256)
  t.is(outcomes.filter(result => result === 'REGISTRY_BUSY').length, 1792, 'overload reports retry, never a false success')
  t.is(writes.size, 256, 'every accepted mutation has its cache row')
  t.is(registry._acceptances.size, 256)
  t.is(stats().peak, 64)
  t.is(registry._pendingMutations, 0)
  t.is(registry._keyLocks.size, 0)
  t.is(registry._pendingIndexOps.size, 0)
  t.ok(log.closed)
})

test('registry synchronous custody push declines busy ingress and permits retry after drain', async t => {
  const { registry, putGate, writes } = await setup()
  for (let i = 1; i <= 64; i++) registry._applyEntry(acceptance(i))
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  const intent = createCustodyIntent({ blindContentId: hex(33), ciphertextRoot: hex(34), requiredReplicas: 2, contentVersion: 1, deadline: Date.now() + 60000, retainUntil: Date.now() + 3600000 }, { publicKey, secretKey })
  t.absent(registry._applyPushedEntry(intent, hex(7)), 'busy push explicitly declines before applying')
  t.is(registry._custodyIntents.size, 0)
  t.is(registry._pendingIndexOps.size, 64)
  putGate.resolve()
  await registry._flushIndexBee()
  t.ok(registry._applyPushedEntry(intent, hex(7)), 'same signed entry remains admissible on retry')
  await registry.stop()
  t.ok(writes.has(`entry:custody-intent:${intent.intentId}`))
})

test('registry reserves opening peer logs against concurrent announcement quota and stop drains ready', async t => {
  const readyGate = gate()
  const logs = []
  const registry = new SeedingRegistry({
    get (key) {
      const log = new Log()
      log.key = key
      log.readyGate = readyGate
      logs.push(log)
      return log
    }
  }, null, { maxPeerLogs: 8 })
  const localLog = new Log()
  registry.localLog = localLog
  const registrations = []
  for (let i = 2; i <= 2049; i++) registrations.push(registry._registerPeerLog(hex(i), hex(i), {}))
  t.is(logs.length, 8, 'opening logs consume quota before ready can resolve')
  t.is(registry._peerLogRegistrations.size, 8)
  await registry._registerPeerLog(hex(2), hex(2), {})
  t.is(logs.length, 8, 'duplicate key cannot create another opening owner')
  const stopped = registry.stop()
  await turn()
  t.absent(localLog.closed, 'shutdown waits for admitted opening cores')
  readyGate.resolve()
  await Promise.all(registrations)
  await stopped
  t.ok(logs.every(log => log.closed))
  t.is(registry._peerLogRegistrations.size, 0)
  t.is(registry.peerLogs.size, 0)
  t.is(registry._peerLogMeta.size, 0)
})

for (const phase of ['ready', 'replicate']) {
  test(`registry failed peer ${phase} retires the session before retry reclaims its slot`, async t => {
    const closeGate = gate()
    const failed = new Log(2)
    failed[phase] = () => { throw new Error(`injected ${phase} failure`) }
    failed.close = async () => { await closeGate.promise; failed.closed = true }
    const retried = new Log(2)
    await retried.append(b4a.from(JSON.stringify(acceptance(2))))
    const sessions = [failed, retried]
    let opens = 0
    const registry = new SeedingRegistry({ get: () => sessions[opens++] }, null, { maxPeerLogs: 1 })
    registry.localLog = new Log()
    const opening = registry._registerPeerLog(hex(2), hex(7), {}).catch(err => err.message)
    await turn()
    t.is(registry.peerLogs.get(hex(2)), failed, 'failed session owns quota until close settles')
    t.is(registry._peerLogRegistrations.size, 1, 'retirement remains owned by opening promise')
    await registry._registerPeerLog(hex(3), hex(8), {})
    t.is(opens, 1, 'another admission cannot reuse the unclosed slot')
    closeGate.resolve()
    t.is(await opening, `injected ${phase} failure`)
    t.ok(failed.closed)
    t.is(registry._peerLogMeta.size, 0, 'successful retirement reclaims metadata and quota')
    t.is(registry.peerLogs.size, 0)
    await registry._registerPeerLog(hex(2), hex(7), {})
    t.is(opens, 2, 'same log key opens a new session on retry')
    t.is(registry._acceptances.size, 1, 'retry replays the durable accepted block')
    t.is(retried.listenerCount('append'), 1)
    await registry.stop()
    t.ok(retried.closed)
    t.is(registry._peerLogRegistrations.size, 0)
    t.is(registry.peerLogs.size, 0)
  })
}

test('registry failed opening close retains exact owner until shutdown retries retirement', async t => {
  const failed = new Log(2)
  failed.ready = async () => { throw new Error('injected ready failure') }
  let closes = 0
  failed.close = async () => {
    if (++closes === 1) throw new Error('injected close failure')
    failed.closed = true
  }
  const registry = new SeedingRegistry({ get: () => failed }, null)
  registry.localLog = new Log()
  const errors = []
  registry.on('stop-error', error => errors.push(error))
  t.is(await registry._registerPeerLog(hex(2), hex(7), {}).catch(err => err.message), 'injected ready failure')
  t.is(errors[0].operation, 'failedPeerLog.close')
  t.is(registry.peerLogs.get(hex(2)), failed, 'failed close retains exact handle')
  t.is(registry._peerLogMeta.get(hex(2)).failed, true)
  t.is(await registry._registerPeerLog(hex(2), hex(7), {}).catch(err => err.code), 'REGISTRY_PEER_LOG_RETIREMENT_PENDING', 'same-key ingress reports pending retirement rather than false success')
  await registry.stop()
  t.is(closes, 2, 'shutdown retries the retained close')
  t.ok(failed.closed)
  t.is(registry.peerLogs.size, 0)
  t.is(registry._peerLogMeta.size, 0)
})
