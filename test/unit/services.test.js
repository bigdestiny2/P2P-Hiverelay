import test from 'brittle'
import { ServiceRegistry } from 'p2p-hiverelay/core/services/registry.js'
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import {
  MAX_SERVICE_CATALOG_ENTRIES,
  MAX_SERVICE_DESCRIPTION_BYTES
} from 'p2p-hiverelay/core/services/service-catalog.js'
import { ZKService } from 'p2p-hiveservices/builtin/zk-service.js'
import { AIService } from 'p2p-hiveservices/builtin/ai-service.js'

// ─── Test service for registry tests ────────────────────────────────

class EchoService extends ServiceProvider {
  manifest () {
    return {
      name: 'echo',
      version: '1.0.0',
      description: 'Test echo service',
      capabilities: ['echo', 'ping']
    }
  }

  async echo (params) {
    return { echoed: params }
  }

  async ping () {
    return { pong: true, timestamp: Date.now() }
  }
}

class MathService extends ServiceProvider {
  manifest () {
    return {
      name: 'math',
      version: '2.0.0',
      capabilities: ['add', 'multiply']
    }
  }

  async add (params) { return { result: params.a + params.b } }
  async multiply (params) { return { result: params.a * params.b } }
}

// ─── ServiceRegistry tests ──────────────────────────────────────────

test('ServiceRegistry - register and get service', async (t) => {
  const registry = new ServiceRegistry()
  const echo = new EchoService()

  const entry = registry.register(echo)
  t.is(entry.name, 'echo')
  t.is(entry.version, '1.0.0')
  t.is(registry.services.size, 1)
})

test('ServiceRegistry - reject duplicate service', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  try {
    registry.register(new EchoService())
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('SERVICE_EXISTS'))
  }
})

test('ServiceRegistry - handle RPC request', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  const result = await registry.handleRequest('echo', 'echo', { hello: 'world' }, {})
  t.alike(result, { echoed: { hello: 'world' } })
})

test('ServiceRegistry - reject unknown service', async (t) => {
  const registry = new ServiceRegistry()

  try {
    await registry.handleRequest('missing', 'foo', {}, {})
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('SERVICE_NOT_FOUND'))
  }
})

test('ServiceRegistry - reject unknown method', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  try {
    await registry.handleRequest('echo', 'nonexistent', {}, {})
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('METHOD_NOT_FOUND'))
  }
})

test('ServiceRegistry - catalog returns all services', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())
  registry.register(new MathService())

  const catalog = registry.catalog()
  t.is(catalog.length, 2)
  t.is(catalog[0].name, 'echo')
  t.is(catalog[1].name, 'math')
  t.alike(catalog[0].capabilities, ['echo', 'ping'])
})

test('ServiceRegistry - unregister service', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  const removed = await registry.unregister('echo')
  t.is(removed, true)
  t.is(registry.services.size, 0)

  const notFound = await registry.unregister('echo')
  t.is(notFound, false)
})

test('ServiceRegistry - tracks request stats', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  await registry.handleRequest('echo', 'echo', {}, {})
  await registry.handleRequest('echo', 'ping', {}, {})

  const stats = registry.stats()
  t.is(stats.echo.requests, 2)
  t.is(stats.echo.errors, 0)
})

test('ServiceRegistry - tracks error stats', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  try {
    await registry.handleRequest('echo', 'nonexistent', {}, {})
  } catch {}

  // errors only increment for provider-level errors, not method-not-found
  // (method-not-found is caught before calling provider)
  const stats = registry.stats()
  t.is(stats.echo.requests, 0)
})

test('ServiceRegistry - max services limit', async (t) => {
  const registry = new ServiceRegistry({ maxServices: 1 })
  registry.register(new EchoService())

  try {
    registry.register(new MathService())
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('SERVICE_LIMIT'))
  }
})

test('ServiceRegistry - find providers (local)', async (t) => {
  const registry = new ServiceRegistry()
  registry.register(new EchoService())

  const providers = registry.findProviders('echo')
  t.is(providers.length, 1)
  t.is(providers[0].local, true)
  t.is(providers[0].relay, 'local')
})

test('ServiceRegistry - find providers (remote)', async (t) => {
  const registry = new ServiceRegistry()

  registry.addRemoteServices('abc123', [
    { name: 'storage', version: '1.0.0', capabilities: ['drive-create'] },
    { name: 'ai', version: '1.0.0', capabilities: ['infer'] }
  ])

  const storageProviders = registry.findProviders('storage')
  t.is(storageProviders.length, 1)
  t.is(storageProviders[0].relay, 'abc123')
  t.is(storageProviders[0].local, false)

  const missing = registry.findProviders('identity')
  t.is(missing.length, 0)
})

test('ServiceRegistry - sanitizes remote service catalogs before storing', async (t) => {
  const registry = new ServiceRegistry()
  let update = null
  registry.on('remote-services-updated', (event) => { update = event })

  registry.addRemoteServices('abc123', [
    {
      name: 'storage',
      version: '1.0.0',
      description: 'x'.repeat(MAX_SERVICE_DESCRIPTION_BYTES + 20),
      capabilities: ['get', 'put', 'get'],
      provider: { secret: true }
    },
    { name: 'bad\nname', version: '1.0.0' },
    ...Array.from({ length: MAX_SERVICE_CATALOG_ENTRIES + 5 }, (_, i) => ({
      name: 'svc-' + i,
      version: '1.0.0',
      secretToken: 'nope'
    }))
  ])

  const stored = registry.remoteServices.get('abc123')
  t.ok(stored)
  t.is(stored.services.length, MAX_SERVICE_CATALOG_ENTRIES)
  t.alike(stored.services[0].capabilities, ['get', 'put'])
  t.is(Buffer.byteLength(stored.services[0].description, 'utf8'), MAX_SERVICE_DESCRIPTION_BYTES)
  t.absent(JSON.stringify(stored.services).includes('secretToken'))
  t.absent(JSON.stringify(stored.services).includes('provider'))
  t.alike(update, { relay: 'abc123', count: MAX_SERVICE_CATALOG_ENTRIES })
})

test('ServiceRegistry - version filter in findProviders', async (t) => {
  const registry = new ServiceRegistry()

  registry.addRemoteServices('node1', [{ name: 'echo', version: '1.0.0' }])
  registry.addRemoteServices('node2', [{ name: 'echo', version: '2.0.0' }])

  const all = registry.findProviders('echo')
  t.is(all.length, 2)

  const v2 = registry.findProviders('echo', { minVersion: '2.0.0' })
  t.is(v2.length, 1)
  t.is(v2[0].relay, 'node2')
})

test('ServiceRegistry - startAll and stopAll', async (t) => {
  const registry = new ServiceRegistry()
  let started = 0
  let stopped = 0
  let id = 0

  class TrackingService extends ServiceProvider {
    constructor () { super(); this._id = id++ }
    manifest () { return { name: 'track-' + this._id, version: '1.0.0', capabilities: [] } }
    async start () { started++ }
    async stop () { stopped++ }
  }

  registry.register(new TrackingService())
  registry.register(new TrackingService())

  await registry.startAll({})
  t.is(started, 2, 'both services started')

  await registry.stopAll()
  t.is(stopped, 2, 'both services stopped')
  t.is(registry.services.size, 0, 'services cleared')
})

test('ServiceRegistry - startAll fail-closed unregisters failed service', async (t) => {
  const registry = new ServiceRegistry()

  class GoodService extends ServiceProvider {
    manifest () { return { name: 'good', version: '1.0.0', capabilities: [] } }
    async start () {}
    async stop () {}
  }

  class BadService extends ServiceProvider {
    manifest () { return { name: 'bad', version: '1.0.0', capabilities: [] } }
    async start () { throw new Error('boom') }
    async stop () {}
  }

  registry.register(new GoodService())
  registry.register(new BadService())

  const result = await registry.startAll({})
  t.is(result.failed.length, 1, 'one service failed')
  t.is(result.failed[0].name, 'bad', 'failed service recorded')
  t.is(registry.services.has('good'), true, 'healthy service stays registered')
  t.is(registry.services.has('bad'), false, 'failed service removed')
})

test('ServiceRegistry - failed start strictly stops partially-started provider', async (t) => {
  const registry = new ServiceRegistry()
  const events = []

  class PartialService extends ServiceProvider {
    manifest () { return { name: 'partial', version: '1.0.0', capabilities: [] } }
    async start () {
      events.push('resource-open')
      throw new Error('injected start failure')
    }

    async stop () { events.push('resource-closed') }
  }

  registry.register(new PartialService())
  const result = await registry.startAll({})
  t.alike(events, ['resource-open', 'resource-closed'], 'partial resource settles before return')
  t.is(result.failed.length, 1)
  t.is(registry.services.has('partial'), false, 'settled failed provider is removed')
})

test('ServiceRegistry - failed startup teardown retains provider for strict retry', async (t) => {
  const registry = new ServiceRegistry()
  let rejectStop = true
  let stops = 0

  class PartialService extends ServiceProvider {
    manifest () { return { name: 'partial-retry', version: '1.0.0', capabilities: [] } }
    async start () { throw new Error('injected start failure') }
    async stop () {
      stops++
      if (rejectStop) throw new Error('injected stop failure')
    }
  }

  registry.register(new PartialService())
  await t.exception(registry.startAll({}), /startup teardown did not settle/)
  t.is(registry.services.get('partial-retry')?.status, 'start-stop-failed')
  rejectStop = false
  await registry.stopAll({ throwOnError: true })
  t.is(stops, 2, 'failed provider stop retried exactly once')
  t.is(registry.services.size, 0)
})

test('ServiceRegistry - runtime failed service fails closed and can restart', async (t) => {
  const registry = new ServiceRegistry()
  let starts = 0
  let stops = 0

  class FlakyService extends ServiceProvider {
    manifest () { return { name: 'flaky', version: '1.0.0', capabilities: ['echo'] } }
    async start () { starts++ }
    async stop () { stops++ }
    async echo (params) { return params }
  }

  registry.register(new FlakyService())
  await registry.startAll({})

  const before = await registry.handleRequest('flaky', 'echo', { ok: true }, {})
  t.alike(before, { ok: true }, 'running service handles request')

  registry.markFailed('flaky', new Error('runtime boom'))
  try {
    await registry.handleRequest('flaky', 'echo', { ok: false }, {})
    t.fail('failed service should reject requests')
  } catch (err) {
    t.ok(err.message.includes('SERVICE_UNAVAILABLE'), 'failed service fails closed')
  }

  await registry.restart('flaky', {})
  const after = await registry.handleRequest('flaky', 'echo', { ok: true }, {})
  t.alike(after, { ok: true }, 'restarted service handles request')
  t.is(starts, 2, 'service restarted')
  t.is(stops, 1, 'service stopped before restart')
})

// ─── ZKService tests (secp256k1 EC-based) ──────────────────────────

test('ServiceRegistry - rejects start without matching stop authority', async (t) => {
  const registry = new ServiceRegistry()
  class UnsafeService extends ServiceProvider {
    manifest () { return { name: 'unsafe-lifecycle', version: '1.0.0', capabilities: [] } }
    async start () {}
  }
  try {
    registry.register(new UnsafeService())
    t.fail('unsafe provider should be rejected')
  } catch (err) {
    t.is(err.code, 'SERVICE_INVALID_LIFECYCLE')
  }
  t.is(registry.services.size, 0)
})

test('ServiceRegistry - default stopAll retains a provider whose stop rejects', async (t) => {
  const registry = new ServiceRegistry()
  class StickyService extends ServiceProvider {
    manifest () { return { name: 'sticky-stop', version: '1.0.0', capabilities: [] } }
    async start () {}
    async stop () { throw new Error('injected stop failure') }
  }
  registry.register(new StickyService())
  await registry.startAll({})
  await registry.stopAll()
  t.is(registry.services.get('sticky-stop')?.status, 'stop-failed')
  t.is(registry.services.size, 1, 'failed owner remains registered for retry')
})

test('ServiceRegistry - failed restart stop never starts the provider again', async (t) => {
  const registry = new ServiceRegistry()
  let starts = 0
  class StopFailureService extends ServiceProvider {
    manifest () { return { name: 'restart-stop-failure', version: '1.0.0', capabilities: [] } }
    async start () { starts++ }
    async stop () { throw new Error('injected restart stop failure') }
  }
  registry.register(new StopFailureService())
  await registry.startAll({})
  await t.exception(registry.restart('restart-stop-failure'), /SERVICE_RESTART_STOP_FAILED/)
  t.is(starts, 1, 'restart start is never entered after failed stop')
  t.is(registry.services.get('restart-stop-failure')?.status, 'stop-failed')
})

test('ServiceRegistry - failed restart start strictly retains failed cleanup owner', async (t) => {
  const registry = new ServiceRegistry()
  let starts = 0
  let stops = 0
  class PartialRestartService extends ServiceProvider {
    manifest () { return { name: 'partial-restart', version: '1.0.0', capabilities: [] } }
    async start () {
      starts++
      if (starts > 1) throw new Error('injected restart start failure')
    }

    async stop () {
      stops++
      if (stops > 1) throw new Error('injected restart cleanup failure')
    }
  }
  registry.register(new PartialRestartService())
  await registry.startAll({})
  let failure = null
  try { await registry.restart('partial-restart') } catch (err) { failure = err }
  t.is(failure?.code, 'SERVICE_RESTART_START_TEARDOWN_FAILED')
  t.is(failure?.startCause?.message, 'injected restart start failure')
  t.is(failure?.teardownCause?.message, 'injected restart cleanup failure')
  t.is(registry.services.get('partial-restart')?.status, 'restart-start-stop-failed')
})

test('ServiceRegistry - synchronous stop intent cancels a gated restart without duplicate stop', async (t) => {
  const registry = new ServiceRegistry()
  let starts = 0
  let stops = 0
  let releaseStop = null
  const stopGate = new Promise(resolve => { releaseStop = resolve })
  class GatedRestartService extends ServiceProvider {
    manifest () { return { name: 'gated-restart', version: '1.0.0', capabilities: [] } }
    async start () { starts++ }
    async stop () { stops++; await stopGate }
  }
  registry.register(new GatedRestartService())
  await registry.startAll({})
  const restarting = registry.restart('gated-restart')
  await new Promise(resolve => setTimeout(resolve, 0))
  const stopping = registry.stopAll({ throwOnError: true })
  releaseStop()
  const [restartResult, stopResult] = await Promise.allSettled([restarting, stopping])
  t.is(restartResult.reason?.code, 'SERVICE_RESTART_CANCELLED')
  t.is(stopResult.status, 'fulfilled')
  t.is(starts, 1, 'no detached restart occurs after stop intent')
  t.is(stops, 1, 'queued stopAll does not stop an already-stopped owner twice')
  t.is(registry.services.size, 0)
})

test('ServiceRegistry - stop intent settles gated startAll and blocks dispatch', async (t) => {
  const registry = new ServiceRegistry()
  let releaseStart = null
  const startGate = new Promise(resolve => { releaseStart = resolve })
  let firstStarts = 0
  let firstStops = 0
  let secondStarts = 0
  class FirstService extends ServiceProvider {
    manifest () { return { name: 'gated-first', version: '1.0.0', capabilities: ['echo'] } }
    async start () { firstStarts++; await startGate }
    async stop () { firstStops++ }
    async echo (params) { return params }
  }
  class SecondService extends ServiceProvider {
    manifest () { return { name: 'gated-second', version: '1.0.0', capabilities: [] } }
    async start () { secondStarts++ }
    async stop () {}
  }
  registry.register(new FirstService())
  registry.register(new SecondService())
  const starting = registry.startAll({})
  await new Promise(resolve => setTimeout(resolve, 0))
  const stopping = registry.stopAll({ throwOnError: true })
  await t.exception(
    registry.handleRequest('gated-first', 'echo', {}, {}),
    /lifecycle mutation pending/
  )
  releaseStart()
  await Promise.all([starting, stopping])
  t.is(firstStarts, 1)
  t.is(firstStops, 1, 'in-flight start owner is settled exactly once')
  t.is(secondStarts, 0, 'later providers never start after stop intent')
  t.is(registry.services.size, 0)
})

test('ServiceRegistry - stop intent during restart start tears down exact owner without restarted event', async (t) => {
  const registry = new ServiceRegistry()
  let starts = 0
  let stops = 0
  let restartedEvents = 0
  let releaseRestartStart = null
  let restartStartEntered = null
  const startGate = new Promise(resolve => { releaseRestartStart = resolve })
  const entered = new Promise(resolve => { restartStartEntered = resolve })
  class GatedPostStartService extends ServiceProvider {
    manifest () { return { name: 'gated-post-start', version: '1.0.0', capabilities: [] } }
    async start () {
      starts++
      if (starts > 1) {
        restartStartEntered()
        await startGate
      }
    }

    async stop () { stops++ }
  }
  registry.on('service-restarted', () => { restartedEvents++ })
  registry.register(new GatedPostStartService())
  await registry.startAll({})
  const restarting = registry.restart('gated-post-start')
  await entered
  const stopping = registry.stopAll({ throwOnError: true })
  releaseRestartStart()
  const [restartResult, stopResult] = await Promise.allSettled([restarting, stopping])
  t.is(restartResult.reason?.code, 'SERVICE_RESTART_CANCELLED')
  t.is(stopResult.status, 'fulfilled')
  t.is(starts, 2)
  t.is(stops, 2, 'pre-restart stop plus immediate post-start teardown, with no duplicate queued stop')
  t.is(restartedEvents, 0)
  t.is(registry.services.size, 0)
})

test('ZKService - manifest v2', async (t) => {
  const svc = new ZKService()
  const m = svc.manifest()
  t.is(m.name, 'zk')
  t.is(m.version, '2.0.0')
  t.ok(m.capabilities.includes('commit'))
  t.ok(m.capabilities.includes('prove-knowledge'))
  t.ok(m.capabilities.includes('prove-dleq'))
  t.ok(m.capabilities.includes('encrypt-card'))
  t.ok(m.capabilities.includes('commit-random'))
  t.ok(m.capabilities.includes('prove-membership'))
  t.ok(m.capabilities.includes('prove-range'))
})

test('ZKService - Pedersen commit and verify', async (t) => {
  const svc = new ZKService()

  const { commitment, blindingFactor } = await svc.commit({ value: 'secret42' })
  t.ok(commitment)
  t.is(commitment.length, 66) // compressed secp256k1 point
  t.ok(blindingFactor)
  t.is(blindingFactor.length, 64) // 32-byte scalar

  // Correct opening
  const valid = await svc['verify-commit']({ commitment, value: 'secret42', blindingFactor })
  t.is(valid.valid, true)

  // Wrong value
  const invalid = await svc['verify-commit']({ commitment, value: 'wrong', blindingFactor })
  t.is(invalid.valid, false)
})

test('ZKService - Pedersen commit numeric values', async (t) => {
  const svc = new ZKService()
  const { commitment, blindingFactor } = await svc.commit({ value: 1000 })
  const result = await svc['verify-commit']({ commitment, value: 1000, blindingFactor })
  t.is(result.valid, true)

  const wrong = await svc['verify-commit']({ commitment, value: 999, blindingFactor })
  t.is(wrong.valid, false)
})

test('ZKService - Schnorr proof of knowledge', async (t) => {
  const svc = new ZKService()

  // Generate a random secret (64 hex chars = 32 bytes)
  const secret = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')

  const { proof, publicPoint } = await svc['prove-knowledge']({ secret })
  t.ok(proof.R)
  t.is(proof.R.length, 66)
  t.ok(proof.s)
  t.is(publicPoint.length, 66)

  // Verify
  const result = await svc['verify-knowledge']({ proof, publicPoint })
  t.is(result.valid, true)
})

test('ZKService - Schnorr proof wrong public point fails', async (t) => {
  const svc = new ZKService()
  const secret1 = '0a' + '0'.repeat(62)
  const secret2 = '0b' + '0'.repeat(62)

  const { proof } = await svc['prove-knowledge']({ secret: secret1 })
  const { publicPoint: wrongPoint } = await svc['prove-knowledge']({ secret: secret2 })

  const result = await svc['verify-knowledge']({ proof, publicPoint: wrongPoint })
  t.is(result.valid, false)
})

test('ZKService - DLEQ proof', async (t) => {
  const svc = new ZKService()
  const secret = '05' + '0'.repeat(62)

  // Create two base points and compute x*G1, x*G2
  const { publicPoint: A } = await svc['prove-knowledge']({ secret })
  // Use the proof's public point as G (generator), and another point as H
  const G1 = await svc['prove-knowledge']({ secret: '01' + '0'.repeat(62) })
  const H1 = await svc['prove-knowledge']({ secret: '02' + '0'.repeat(62) })

  // For DLEQ we need: secret, G, A=secret*G, H, B=secret*H
  // Use the standard generator
  const { proof } = await svc['prove-dleq']({
    secret,
    G: G1.publicPoint,
    A,
    H: H1.publicPoint,
    B: await (async () => {
      // Compute secret * H1
      const { publicPoint } = await svc['prove-knowledge']({ secret })
      return publicPoint // This is secret * G, not secret * H1
    })()
  })
  t.ok(proof.e)
  t.ok(proof.s)
})

test('ZKService - ElGamal card encrypt and unmask (single player)', async (t) => {
  const svc = new ZKService()
  const secretKey = '07' + '0'.repeat(62)
  const { publicPoint: publicKey } = await svc['prove-knowledge']({ secret: secretKey })

  // Encrypt card 7
  const { encrypted } = await svc['encrypt-card']({ card: 7, publicKey })
  t.ok(encrypted.c1)
  t.ok(encrypted.c2)
  t.is(encrypted.c1.length, 66)

  // Create reveal token
  const { token, proof } = await svc['create-reveal-token']({ encrypted, secretKey })
  t.ok(token)
  t.ok(proof)

  // Unmask
  const { card } = await svc['unmask-card']({ encrypted, tokens: [token] })
  t.is(card, 7)
})

test('ZKService - ElGamal card encrypt invalid card index', async (t) => {
  const svc = new ZKService()
  try {
    await svc['encrypt-card']({ card: 52, publicKey: '02' + '0'.repeat(64) })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('ZK_INVALID_CARD'))
  }
})

test('ZKService - unmask with wrong token returns -1', async (t) => {
  const svc = new ZKService()
  const sk1 = '07' + '0'.repeat(62)
  const sk2 = '09' + '0'.repeat(62)
  const { publicPoint: pk1 } = await svc['prove-knowledge']({ secret: sk1 })

  const { encrypted } = await svc['encrypt-card']({ card: 3, publicKey: pk1 })

  // Use wrong secret key for token
  const { token: wrongToken } = await svc['create-reveal-token']({ encrypted, secretKey: sk2 })
  const { card } = await svc['unmask-card']({ encrypted, tokens: [wrongToken] })
  t.is(card, -1) // Card not found
})

test('ZKService - fair randomness commit-reveal', async (t) => {
  const svc = new ZKService()

  // 3 players commit
  const p1 = await svc['commit-random']()
  const p2 = await svc['commit-random']()
  const p3 = await svc['commit-random']()

  t.ok(p1.commitment)
  t.ok(p1.secret)

  // Combine reveals
  const result = await svc['combine-reveals']({
    reveals: [
      { secret: p1.secret, commitment: p1.commitment },
      { secret: p2.secret, commitment: p2.commitment },
      { secret: p3.secret, commitment: p3.commitment }
    ]
  })
  t.is(result.valid, true)
  t.ok(result.randomValue)
  t.is(result.randomValue.length, 64)
})

test('ZKService - fair randomness detects cheater', async (t) => {
  const svc = new ZKService()
  const p1 = await svc['commit-random']()

  const result = await svc['combine-reveals']({
    reveals: [
      { secret: 'ff'.repeat(32), commitment: p1.commitment } // wrong secret
    ]
  })
  t.is(result.valid, false)
  t.is(result.failedIndex, 0)
})

test('ZKService - membership proof (no plaintext in verify)', async (t) => {
  const svc = new ZKService()
  const set = ['alice', 'bob', 'carol', 'dave']

  const proof = await svc['prove-membership']({ value: 'carol', set })
  t.ok(proof.leafHash)
  t.ok(proof.merkleRoot)
  t.ok(proof.proof.length > 0)

  // Verify with leafHash only — no plaintext value needed
  const result = await svc['verify-membership']({
    leafHash: proof.leafHash,
    merkleRoot: proof.merkleRoot,
    proof: proof.proof,
    leafIndex: proof.leafIndex
  })
  t.is(result.valid, true)
})

test('ZKService - membership proof rejects non-member', async (t) => {
  const svc = new ZKService()
  try {
    await svc['prove-membership']({ value: 'eve', set: ['alice', 'bob'] })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('ZK_NOT_IN_SET'))
  }
})

test('ZKService - range proof (no plaintext in verify)', async (t) => {
  const svc = new ZKService()

  const proof = await svc['prove-range']({ value: 25, min: 18, max: 65 })
  t.ok(proof.commitment)
  t.ok(proof.rangeProof)

  // Verify WITHOUT passing the value — only commitment + rangeProof
  const result = await svc['verify-range']({
    commitment: proof.commitment,
    rangeProof: proof.rangeProof
  })
  t.is(result.valid, true)
})

test('ZKService - range proof rejects out of range', async (t) => {
  const svc = new ZKService()
  try {
    await svc['prove-range']({ value: 10, min: 18, max: 65 })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('ZK_OUT_OF_RANGE'))
  }
})

test('ZKService - list circuits v2', async (t) => {
  const svc = new ZKService()
  const c = await svc.circuits()
  t.is(c.available.length, 7)
  t.is(c.pluggable, true)
  t.is(c.curve, 'secp256k1')
})

test('ZKService - registerBackend', async (t) => {
  const svc = new ZKService()
  svc.registerBackend('custom-test', { prove: () => 'ok' })
  const c = await svc.circuits()
  t.is(c.available.length, 8) // 7 builtins + 1 custom
  t.ok(c.available.find(a => a.name === 'custom-test'))
})

// ─── AIService tests ────────────────────────────────────────────────

test('AIService - manifest', async (t) => {
  const svc = new AIService()
  const m = svc.manifest()
  t.is(m.name, 'ai')
  t.ok(m.capabilities.includes('infer'))
  t.ok(m.capabilities.includes('embed'))
})

test('AIService - register and list models', async (t) => {
  const svc = new AIService()
  const adminCtx = { role: 'local' }
  await svc['register-model']({ modelId: 'test-llm', type: 'llm' }, adminCtx)
  await svc['register-model']({ modelId: 'test-embed', type: 'embedding' }, adminCtx)

  const list = await svc['list-models']()
  t.is(list.length, 2)
  t.is(list[0].modelId, 'test-llm')
  t.is(list[1].type, 'embedding')
})

test('AIService - remove model', async (t) => {
  const svc = new AIService()
  const adminCtx = { role: 'local' }
  await svc['register-model']({ modelId: 'tmp', type: 'llm' }, adminCtx)
  const result = await svc['remove-model']({ modelId: 'tmp' }, adminCtx)
  t.is(result.removed, true)

  const list = await svc['list-models']()
  t.is(list.length, 0)
})

test('AIService - infer with handler', async (t) => {
  const svc = new AIService()
  await svc['register-model']({ modelId: 'echo-model', type: 'llm' }, { role: 'local' })
  svc.registerHandler('echo-model', async (req) => {
    return { output: 'echoed: ' + req.input, tokens: 5 }
  })

  const result = await svc.infer({ modelId: 'echo-model', input: 'hello' })
  t.is(result.state, 'complete')
  t.is(result.result.output, 'echoed: hello')
  t.is(result.result.tokens, 5)
})

test('AIService - infer unknown model', async (t) => {
  const svc = new AIService()

  try {
    await svc.infer({ modelId: 'ghost', input: 'test' })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('AI_MODEL_NOT_FOUND'))
  }
})

test('AIService - status', async (t) => {
  const svc = new AIService({ maxConcurrent: 4 })
  await svc['register-model']({ modelId: 'm1', type: 'llm' }, { role: 'local' })

  const s = await svc.status()
  t.is(s.models, 1)
  t.is(s.maxConcurrent, 4)
  t.is(s.queueDepth, 0)
})

test('AIService - queue full', async (t) => {
  const svc = new AIService({ maxQueue: 1, maxConcurrent: 0 })
  await svc['register-model']({ modelId: 'slow', type: 'llm' }, { role: 'local' })
  svc.registerHandler('slow', async () => {
    await new Promise(resolve => setTimeout(resolve, 10000))
  })

  await svc.infer({ modelId: 'slow', input: 'a' })

  try {
    await svc.infer({ modelId: 'slow', input: 'b' })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('AI_QUEUE_FULL'))
  }
})

test('AIService - model registration requires admin context', async (t) => {
  const svc = new AIService()

  try {
    await svc['register-model']({ modelId: 'locked', type: 'llm' }, { remotePubkey: 'peer-a', role: 'authenticated-user' })
    t.fail('non-admin should not register models')
  } catch (err) {
    t.ok(err.message.includes('ACCESS_DENIED'))
  }

  const ok = await svc['register-model']({ modelId: 'admin-model', type: 'llm' }, { role: 'relay-admin' })
  t.is(ok.registered, true, 'admin can register model')
})

test('AIService - per-caller queue limit', async (t) => {
  const svc = new AIService({ maxConcurrent: 0, maxJobsPerCaller: 1 })
  await svc['register-model']({ modelId: 'q', type: 'llm' }, { role: 'relay-admin' })
  svc.registerHandler('q', async () => ({ text: 'ok' }))

  await svc.infer({ modelId: 'q', input: 'one' }, { remotePubkey: 'peer-a' })

  try {
    await svc.infer({ modelId: 'q', input: 'two' }, { remotePubkey: 'peer-a' })
    t.fail('should reject second queued job for same caller')
  } catch (err) {
    t.ok(err.message.includes('AI_CALLER_QUEUE_FULL'))
  }
})

test('AIService - qvac infer via injected SDK', async (t) => {
  const calls = []
  const sdk = {
    loadModel: async (params) => {
      calls.push({ op: 'loadModel', params })
      return 'qvac-loaded-llm'
    },
    completion: (params) => {
      calls.push({ op: 'completion', params })
      return {
        final: Promise.resolve({
          content: `qvac: ${params.history[0].content}`,
          stats: { totalTokens: 7 }
        })
      }
    },
    unloadModel: async (params) => {
      calls.push({ op: 'unloadModel', params })
    }
  }
  const svc = new AIService({ qvac: { sdk } })

  await svc['register-model']({
    modelId: 'local-qvac',
    type: 'llm',
    backend: 'qvac',
    modelSrc: '/models/tiny.gguf',
    modelType: 'llm',
    modelConfig: { ctx_size: 256 }
  }, { role: 'local' })

  const result = await svc.infer({ modelId: 'local-qvac', input: 'hello' })
  t.is(result.state, 'complete')
  t.is(result.result.text, 'qvac: hello')
  t.is(result.result.backend, 'qvac')
  t.is(result.result.tokens, 7)
  t.is(result.result.qvac.modelId, 'qvac-loaded-llm')
  t.alike(calls[0], {
    op: 'loadModel',
    params: {
      modelSrc: '/models/tiny.gguf',
      modelType: 'llm',
      modelConfig: { ctx_size: 256 }
    }
  })
  t.is(calls[1].op, 'completion')
  t.alike(calls[1].params.history, [{ role: 'user', content: 'hello' }])

  const list = await svc['list-models']()
  t.is(list[0].backend, 'qvac')
  t.is(list[0].qvac.loaded, true)

  await svc.stop()
  t.ok(calls.find(c => c.op === 'unloadModel' && c.params.modelId === 'qvac-loaded-llm'))
})

test('AIService - remove qvac model unloads HiveRelay-loaded model', async (t) => {
  const calls = []
  const sdk = {
    loadModel: async () => {
      calls.push({ op: 'loadModel' })
      return 'qvac-loaded-remove'
    },
    completion: async () => ({ text: 'ok', stats: { tokens: 1 } }),
    unloadModel: async (params) => {
      calls.push({ op: 'unloadModel', params })
    }
  }
  const svc = new AIService({ qvac: { sdk } })

  await svc['register-model']({
    modelId: 'remove-qvac',
    type: 'llm',
    backend: 'qvac',
    modelSrc: '/models/remove.gguf'
  }, { role: 'relay-admin' })

  await svc.infer({ modelId: 'remove-qvac', input: 'hello' })
  const removed = await svc['remove-model']({ modelId: 'remove-qvac' }, { role: 'relay-admin' })
  t.is(removed.removed, true)
  t.ok(calls.find(c => c.op === 'unloadModel' && c.params.modelId === 'qvac-loaded-remove'))

  const list = await svc['list-models']()
  t.is(list.length, 0)
})

test('AIService - qvac embed via injected SDK', async (t) => {
  const sdk = {
    loadModel: async () => 'qvac-loaded-embed',
    embed: async (params) => ({
      embedding: [0.1, 0.2, 0.3],
      stats: { tokens: params.text.length }
    })
  }
  const svc = new AIService({ qvac: { sdk } })

  await svc['register-model']({
    modelId: 'local-qvac-embed',
    type: 'embedding',
    backend: 'qvac',
    modelSrc: '/models/embed.gguf',
    modelType: 'embedding'
  }, { role: 'local' })

  const result = await svc.embed({ modelId: 'local-qvac-embed', input: 'abc' })
  t.alike(result.embedding, [0.1, 0.2, 0.3])
  t.is(result.backend, 'qvac')
  t.is(result.tokens, 3)
  t.is(result.qvac.modelId, 'qvac-loaded-embed')
})

test('AIService - qvac unavailable falls back to HTTP endpoint', async (t) => {
  const svc = new AIService({
    qvac: {
      importModule: async () => {
        throw new Error('not installed')
      }
    }
  })
  svc._httpInfer = async () => ({ text: 'http fallback', tokens: 2, model: 'fallback-model' })
  await svc['register-model']({
    modelId: 'fallback',
    type: 'llm',
    backend: 'qvac',
    endpoint: 'http://127.0.0.1:11434/api/generate',
    modelSrc: '/models/missing.gguf'
  }, { role: 'local' })

  const result = await svc.infer({ modelId: 'fallback', input: 'hello' })
  t.is(result.state, 'complete')
  t.is(result.result.text, 'http fallback')
  t.is(result.result.tokens, 2)

  const status = await svc.status()
  t.is(status.qvac.checked, true)
  t.is(status.qvac.available, false)
  t.ok(status.qvac.error.includes('not installed'))
})
