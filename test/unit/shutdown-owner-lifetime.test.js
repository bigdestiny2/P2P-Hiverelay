import test from 'brittle'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { SeedingRegistry } from '../../packages/core/core/registry/index.js'

const turn = () => new Promise(resolve => setImmediate(resolve))
function gate () {
  let resolve
  const promise = new Promise(_resolve => { resolve = _resolve })
  return { promise, resolve }
}

test('registry stop shares exact pending discovery and drains index writes before cancellation', async t => {
  const registry = new SeedingRegistry({}, {})
  const index = gate()
  const discovery = gate()
  const events = []
  registry._pendingIndexOps.add(index.promise)
  index.promise.then(() => registry._pendingIndexOps.delete(index.promise))
  registry.localLog = { async close () { events.push('log-close') } }
  let destroyed = false
  registry._discoveryHandle = {
    async destroy () {
      // Mirror the pinned real session's early destroyed flag.
      if (destroyed) return
      destroyed = true
      events.push('discovery-start')
      await discovery.promise
      events.push('discovery-done')
    }
  }
  const quiescing = registry.quiesce()
  t.is(registry.quiesce(), quiescing)
  await turn()
  t.alike(events, [], 'index write keeps network and storage ownership')
  index.resolve()
  await quiescing
  t.alike(events, [], 'data quiescence leaves discovery and logs owned')
  const first = registry.stop()
  t.is(registry.stop(), first, 'repeated stop shares its exact promise')
  await turn()
  t.alike(events, ['discovery-start'])
  t.is(registry.stop(), first, 'early transport destroyed flag cannot bypass pending cleanup')
  t.ok(registry.localLog)
  discovery.resolve()
  await first
  t.alike(events, ['discovery-start', 'discovery-done', 'log-close'])
  t.is(registry.localLog, null)
})

test('terminal cancellation and log-close errors retain registry owners for retry', async t => {
  const registry = new SeedingRegistry({}, {})
  const error = new Error('injected network cancellation failure')
  let rejectNetwork = true
  let rejectClose = true
  let calls = 0
  const log = { async close () { if (rejectClose) throw new Error('injected log close failure') } }
  const handle = { async destroy () { calls++; if (rejectNetwork) throw error } }
  registry.localLog = log
  registry._discoveryHandle = handle
  t.is(await registry.stop().catch(err => err), error)
  t.is(registry.localLog, log)
  t.is(registry._discoveryHandle, handle)
  t.is(calls, 1)
  t.is(await registry._withKeyLock('new', () => true).catch(err => err.code), 'REGISTRY_STOPPING')
  rejectNetwork = false
  await t.exception(registry.stop(), /injected log close failure/)
  t.is(registry.localLog, log, 'failed storage close remains owned')
  t.is(calls, 2)
  rejectClose = false
  await registry.stop()
  t.is(registry.localLog, null)
  t.is(calls, 2, 'settled discovery is not destroyed twice')
})

test('owner timeout retains the actual operation and retry cannot overtake settlement', async t => {
  const node = Object.create(RelayNode.prototype)
  node._ownerOperations = new WeakMap()
  const owner = {}
  const pending = gate()
  let calls = 0
  const run = () => { calls++; return pending.promise }
  const setTimeout = globalThis.setTimeout
  let expire
  globalThis.setTimeout = (fn, ms, ...args) => {
    if (ms === 10000) { expire = fn; return setTimeout(() => {}, 60000) }
    return setTimeout(fn, ms, ...args)
  }
  let first
  try {
    first = node._awaitOwnerOperation(owner, 'pending.destroy', run, 1).catch(error => error)
  } finally {
    globalThis.setTimeout = setTimeout
  }
  await turn()
  expire()
  const failure = await first
  t.is(failure.code, 'OPERATION_TIMEOUT')
  t.ok(node._ownerOperations.has(owner), 'timeout leaves the underlying cleanup owned')
  let retried = false
  const second = node._awaitOwnerOperation(owner, 'pending.destroy', run, 1).then(() => { retried = true })
  await turn()
  t.is(calls, 1, 'retry does not reinvoke an idempotent transport method early')
  t.absent(retried)
  pending.resolve()
  await second
  t.is(calls, 1)
  t.absent(node._ownerOperations.has(owner))
})

test('terminal DHT cancellation shares pending work and permits retry only after real failure', async t => {
  const node = Object.create(RelayNode.prototype)
  const pending = gate()
  let calls = 0
  const dht = { async destroy (options) { t.alike(options, { force: true }); calls++; await pending.promise } }
  node.swarm = { dht }
  const first = node._cancelDiscoveryTransport()
  t.is(node._cancelDiscoveryTransport(), first)
  await turn()
  t.is(calls, 1)
  pending.resolve()
  await first
  t.is(node._cancelDiscoveryTransport(), first, 'settled cancellation is not repeated on the same DHT')
  let reject = true
  node.swarm = { dht: { async destroy () { if (reject) throw new Error('injected DHT failure') } } }
  await t.exception(node._cancelDiscoveryTransport(), /injected DHT failure/)
  reject = false
  await node._cancelDiscoveryTransport()
  t.pass('new DHT owner can finish after a genuine failed attempt')
})
