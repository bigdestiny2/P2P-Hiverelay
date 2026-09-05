import { createSocket } from 'node:dgram'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import createTestnet from '@hyperswarm/testnet'
import { RelayNode } from '../../../packages/core/core/relay-node/index.js'
import { measureStorageTreeBytes } from '../../../packages/core/config/storage-cap.js'

const mode = process.argv[2]
const check = (value, message) => { if (!value) throw new Error(message) }
const turn = () => new Promise(resolve => setImmediate(resolve))
const storage = await mkdtemp(join(tmpdir(), 'offline-discovery-shutdown-'))
const blackhole = createSocket('udp4')
await new Promise(resolve => blackhole.bind(0, '127.0.0.1', resolve))
let packets = 0
blackhole.on('message', () => { packets++ })
let generation = 0
const events = []
const testnet = mode === 'online' ? await createTestnet(2) : null
const node = new RelayNode({
  storage,
  bootstrapNodes: testnet?.bootstrap || [{ host: '127.0.0.1', port: blackhole.address().port }],
  enableSeeding: mode !== 'disabled',
  enableAPI: false,
  enableNetworkDiscovery: false,
  enableHolesail: false,
  dhtFlushTimeoutMs: 30,
  physicalEnforcer: {
    schemaVersion: 1,
    async installAbsoluteCeiling (request) {
      return { providerId: 'test-provider', scopeId: 'test-root', leaseId: 'test-lease', operationId: request.operationId, requestedAt: request.requestedAt, rootIdentity: { ...request.storageIdentity }, hardLimitBytes: request.ceilingAllocatedBytes, generation: ++generation }
    },
    async inspectAbsoluteCeiling (lease) {
      return { schemaVersion: 1, active: true, exclusive: true, providerId: lease.providerId, scopeId: lease.scopeId, leaseId: lease.leaseId, operationId: lease.operationId, rootIdentity: { ...lease.rootIdentity }, usedAllocatedBytes: measureStorageTreeBytes(storage), hardLimitBytes: lease.hardLimitBytes, generation: lease.generation, checkedAt: Math.max(Date.now(), lease.requestedAt) }
    }
  }
})
let swarm
try {
  if (mode === 'rollback') {
    node._openStorageIngress = () => { throw new Error('injected startup failure') }
    const started = await node.start().then(() => null, error => error)
    check(started?.message === 'injected startup failure', 'rollback replaced the original startup error')
    check(!node._startupRollbackPending && node.store.closed && node.swarm === null, 'offline rollback retained unfinished teardown')
    await node.stop()
    console.log(JSON.stringify({ ok: true, mode, packets, rollback: 'settled' }))
  } else {
    await node.start()
    swarm = node.swarm
    const store = node.store
    let listeningSettled = false
    swarm.listening?.then(() => { listeningSettled = true }, () => { listeningSettled = true })
    if (testnet) await swarm.listening
    await turn()
    check(swarm.listening && listeningSettled === !!testnet, 'fixture requires the expected real DHT listen state')
    const originalDestroy = swarm.dht.destroy.bind(swarm.dht)
    let cancellationCalls = 0
    let rejectCancellation = mode === 'cancel-failure'
    swarm.dht.destroy = async options => {
      if (options?.force) { cancellationCalls++; events.push('dht-cancel') }
      check(!store.closed, 'transport cancellation released storage first')
      if (rejectCancellation) throw new Error('injected DHT cancellation failure')
      return originalDestroy(options)
    }
    const originalClose = store.close.bind(store)
    store.close = async () => {
      check(swarm.destroyed && swarm.dht.destroyed, 'store closed before transport cleanup')
      events.push('store-close')
      return originalClose()
    }
    let release
    let mutation
    if (mode === 'pending-success' || mode === 'pending-failure') {
      const registry = node.seedingRegistry
      check(registry, 'registry required')
      const append = registry.localLog.append.bind(registry.localLog)
      const gate = new Promise(resolve => { release = resolve })
      let entered
      const entry = new Promise(resolve => { entered = resolve })
      registry.localLog.append = async (...args) => {
        entered()
        await gate
        check(!store.closed, 'storage released before pending append')
        events.push('append-settled')
        if (mode === 'pending-failure') throw Object.assign(new Error('injected append failure'), { code: 'EIO' })
        return append(...args)
      }
      mutation = registry.recordAcceptance('a'.repeat(64), 'b'.repeat(64), 'eu').then(() => 'committed', error => error.code)
      await entry
    }
    const startedAt = Date.now()
    let stopping = node.stop()
    check(node.stop() === stopping, 'concurrent stop must share settlement')
    if (rejectCancellation) {
      const failure = await stopping.then(() => null, error => error)
      check(failure?.message === 'injected DHT cancellation failure', 'failed cancellation must fail shutdown truthfully')
      check(!store.closed && node.store === store && node.swarm === swarm && node.seedingRegistry?.localLog, 'failed cancellation dropped an owner')
      check(!node._storageIngressReady && !node.storageAdmission._acceptingMutations, 'failed cancellation did not keep storage admission sealed')
      rejectCancellation = false
      stopping = node.stop()
    }
    if (release) {
      await turn()
      check(!store.closed && !swarm.dht.destroyed, 'pending append lost storage or transport ownership')
      check(!events.includes('store-close'), 'close preceded mutation settlement')
      release()
    }
    await stopping
    check(Date.now() - startedAt < 2000, 'offline shutdown waited on unreachable discovery')
    const outcome = mutation ? await mutation : null
    if (mode === 'pending-failure') check(outcome === 'EIO', 'interrupted append returned a positive result')
    if (mode === 'pending-success') check(outcome === 'committed', 'admitted append did not settle')
    check(store.closed && node.swarm === null && !node.running, 'shutdown not settled')
    check(cancellationCalls === (mode === 'cancel-failure' ? 2 : 1), 'terminal cancellation was reentered')
    await node.stop()
    if (release) check(events.indexOf('append-settled') < events.indexOf('dht-cancel'), 'cancellation preceded registry drain')
    console.log(JSON.stringify({ ok: true, mode, packets, elapsedMs: Date.now() - startedAt, outcome, events, cancellationCalls }))
  }
} catch (error) {
  console.error(JSON.stringify({ ok: false, mode, error: error.message, code: error.code, cause: error.cause?.message, events }))
  process.exitCode = 1
  // Failure-only fixture cleanup cancels local networking, then retries the
  // actual owner teardown. Never directly close or delete an owned store.
  const dht = (swarm || node.swarm)?.dht
  if (dht && !dht.destroyed) await dht.destroy({ force: true })
  await node.stop().catch(cleanup => console.error('cleanup:', cleanup.message))
} finally {
  await new Promise(resolve => blackhole.close(resolve))
  if (testnet) await testnet.destroy()
  if (node.store?.closed) await rm(storage, { recursive: true, force: true })
}
