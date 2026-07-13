import test from 'brittle'
import http from 'http'
import { EventEmitter } from 'events'
import { NetworkDiscovery } from 'p2p-hiverelay/core/network-discovery.js'

const MAX_API_OVERVIEW_BYTES = 256 * 1024
const MAX_META_BYTES = 2048
const VALID_HOLESAIL_KEY = 'y'.repeat(52)

function listen (server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
}

function closeServer (server) {
  return new Promise(resolve => server.close(resolve))
}

async function rejects (t, promise, pattern) {
  let err = null
  try {
    await promise
  } catch (e) {
    err = e
  }
  t.ok(err, 'expected rejection')
  t.ok(pattern.test(err.message), `message matches ${pattern}`)
  return err
}

test('network discovery fetches bounded API overview JSON', async (t) => {
  const payload = {
    publicKey: 'a'.repeat(64),
    connections: 2,
    seededApps: 3
  }
  const server = http.createServer((req, res) => {
    t.is(req.url, '/api/overview')
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(payload))
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  const data = await discovery._fetchApi('127.0.0.1', server.address().port)
  t.alike(data, payload)
})

test('network discovery rejects oversized API overview content-length', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Content-Length', String(MAX_API_OVERVIEW_BYTES + 1))
    res.end('{}')
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Response too large/)
})

test('network discovery rejects oversized streamed API overview bodies', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ pad: 'x'.repeat(MAX_API_OVERVIEW_BYTES) }))
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Response too large/)
})

test('network discovery rejects non-object API overview JSON', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end('[]')
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Invalid JSON/)
})

test('network discovery accepts bounded z32 holesail metadata frames', (t) => {
  const pubkey = 'a'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let event = null

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', data => { event = data })

  discovery._handleMetadataFrame(
    pubkey,
    Buffer.from(JSON.stringify({ holesailKey: `hs://0000${VALID_HOLESAIL_KEY}` }))
  )

  t.is(relay.holesailKey, VALID_HOLESAIL_KEY)
  t.alike(event, { publicKey: pubkey, holesailKey: VALID_HOLESAIL_KEY })
})

test('network discovery ignores oversized holesail metadata frames', (t) => {
  const pubkey = 'b'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let events = 0

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', () => { events++ })

  discovery._handleMetadataFrame(pubkey, Buffer.alloc(MAX_META_BYTES + 1, 123))

  t.absent(relay.holesailKey)
  t.is(events, 0)
})

test('network discovery rejects malformed holesail metadata frames', (t) => {
  const pubkey = 'c'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let events = 0

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', () => { events++ })

  discovery._handleMetadataFrame(pubkey, Buffer.from('[]'))
  discovery._handleMetadataFrame(pubkey, Buffer.from('{'))
  discovery._handleMetadataFrame(pubkey, Buffer.from(JSON.stringify({ holesailKey: 'not-valid' })))

  t.absent(relay.holesailKey)
  t.is(events, 0)
})

test('network discovery rejects invalid holesail tunnel keys before connecting', async (t) => {
  const discovery = new NetworkDiscovery()

  await rejects(t, discovery._fetchViaHolesail('not-valid'), /Invalid holesail key/)
})

test('network discovery owns and awaits its shared-swarm discovery handle', async (t) => {
  const events = []
  let settleDiscovery
  const settled = new Promise(resolve => { settleDiscovery = resolve })
  const handle = {
    async destroy () {
      events.push('discovery-destroy-start')
      await settled
      events.push('discovery-destroy-done')
    }
  }
  const swarm = {
    join () { events.push('join'); return handle },
    on (event) { events.push(`on-${event}`) },
    removeListener (event) { events.push(`remove-${event}`) },
    async flush () { events.push('flush') }
  }
  const discovery = new NetworkDiscovery({ swarm })
  await discovery.start()
  t.is(discovery._discoveryHandle, handle)

  const stopping = discovery.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('remove-connection'))
  t.ok(events.includes('discovery-destroy-start'))
  t.absent(events.includes('discovery-destroy-done'))

  settleDiscovery()
  await stopping
  t.is(discovery._discoveryHandle, null)
  t.ok(events.includes('discovery-destroy-done'))
})

test('network discovery retains a rejected discovery handle for retry', async (t) => {
  let rejectDestroy = true
  const handle = {
    async destroy () {
      if (rejectDestroy) throw new Error('injected network discovery failure')
    }
  }
  const swarm = {
    join () { return handle },
    on () {},
    removeListener () {},
    async flush () {}
  }
  const discovery = new NetworkDiscovery({ swarm })
  await discovery.start()

  await t.exception(discovery.stop(), /injected network discovery failure/)
  t.is(discovery._discoveryHandle, handle)
  t.is(discovery.swarm, swarm)

  rejectDestroy = false
  await discovery.stop()
  t.is(discovery._discoveryHandle, null)
  t.is(discovery.swarm, swarm, 'shared swarm remains owned by the relay')
})

test('network discovery stop aborts a hung startup flush before awaiting it', async (t) => {
  let destroys = 0
  let removes = 0
  const handle = { async destroy () { destroys++ } }
  const swarm = {
    join () { return handle },
    on () {},
    removeListener () { removes++ },
    flush () { return new Promise(() => {}) }
  }
  const discovery = new NetworkDiscovery({ swarm, startFlushTimeout: 60_000 })
  const starting = discovery.start()
  await new Promise(resolve => setImmediate(resolve))

  await discovery.stop()
  await t.exception(starting, /aborted/)
  t.is(destroys, 1, 'exact startup discovery handle destroyed once')
  t.is(removes, 1, 'startup connection listener detached')
  t.is(discovery.running, false)
})

test('network discovery bounds startup flush and rolls resources back', async (t) => {
  let destroys = 0
  const handle = { async destroy () { destroys++ } }
  const swarm = {
    join () { return handle },
    on () {},
    removeListener () {},
    flush () { return new Promise(() => {}) }
  }
  const discovery = new NetworkDiscovery({ swarm, startFlushTimeout: 10 })

  await t.exception(discovery.start(), /startup flush timed out/)
  t.is(destroys, 1, 'failed startup destroys exact discovery handle')
  t.is(discovery._discoveryHandle, null)
  t.is(discovery.running, false)
})

test('network discovery bounds hung handle teardown and retains exact owner', async (t) => {
  let settleDestroy
  let destroys = 0
  const pending = new Promise(resolve => { settleDestroy = resolve })
  const handle = {
    destroy () {
      destroys++
      return pending
    }
  }
  const swarm = {
    join () { return handle },
    on () {},
    removeListener () {},
    async flush () {}
  }
  const discovery = new NetworkDiscovery({ swarm, stopTimeout: 10 })
  await discovery.start()

  await t.exception(discovery.stop(), /handle destroy timed out/)
  t.is(discovery._discoveryHandle, handle, 'timed-out owner retained')
  t.is(destroys, 1, 'single exact destroy remains in flight')
  settleDestroy()
  await pending
  await discovery.stop()
  t.is(discovery._discoveryHandle, null)
  t.is(destroys, 1, 'retry awaits original destroy instead of duplicating it')
})

test('network discovery preserves startup and teardown causes together', async (t) => {
  const handle = { async destroy () { throw new Error('injected handle teardown failure') } }
  const swarm = {
    join () { return handle },
    on () {},
    removeListener () {},
    async flush () { throw new Error('injected startup flush failure') }
  }
  const discovery = new NetworkDiscovery({ swarm })
  let failure = null
  try { await discovery.start() } catch (err) { failure = err }
  t.is(failure?.code, 'NETWORK_DISCOVERY_START_TEARDOWN_FAILED')
  t.is(failure?.startCause?.message, 'injected startup flush failure')
  t.is(failure?.teardownCause?.message, 'injected handle teardown failure')
  t.is(discovery._discoveryHandle, handle)
})

test('network discovery duplicate connection retains old teardown and never deletes replacement', async (t) => {
  const pubkey = Buffer.alloc(32, 9)
  let rejectOldDestroy = true
  let oldDestroys = 0
  let nextDestroys = 0
  class FakeConnection extends EventEmitter {
    constructor (destroy) { super(); this._destroy = destroy }
    destroy () { return this._destroy() }
  }
  const old = new FakeConnection(async () => {
    oldDestroys++
    if (rejectOldDestroy) throw new Error('injected old connection destroy failure')
  })
  const replacement = new FakeConnection(async () => { nextDestroys++ })
  const discovery = new NetworkDiscovery({ swarm: {}, stopTimeout: 10 })
  discovery._acceptingWork = true
  discovery._lifecycleEpoch = 1
  discovery._onConnection(old, { publicKey: pubkey })
  discovery._onConnection(replacement, { publicKey: pubkey })
  await new Promise(resolve => setTimeout(resolve, 0))
  old.emit('close')
  const key = pubkey.toString('hex')
  t.is(discovery._connections.get(key), replacement, 'old close cannot delete replacement')
  t.is(discovery._retiringConnections.size, 1, 'failed old owner remains retryable')

  await t.exception(discovery.stop(), /injected old connection destroy failure/)
  t.is(nextDestroys, 1, 'current replacement settles once')
  t.is(discovery._retiringConnections.size, 1)
  rejectOldDestroy = false
  await discovery.stop()
  t.is(oldDestroys, 3, 'replacement attempt plus one attempt per stop lifecycle')
  t.is(nextDestroys, 1)
  t.is(discovery._retiringConnections.size, 0)
})

test('network discovery holesail connect timeout destroys exact client and retains failed teardown', async (t) => {
  let rejectDestroy = true
  let destroys = 0
  const client = {
    state: 'connecting',
    connect () {},
    async destroy () {
      destroys++
      if (rejectDestroy) throw new Error('injected holesail destroy failure')
      this.state = 'destroyed'
    }
  }
  const discovery = new NetworkDiscovery({
    holesailConnectTimeout: 5,
    stopTimeout: 10,
    holesailClientFactory: () => client
  })
  discovery._acceptingWork = true
  discovery._lifecycleEpoch = 1
  let failure = null
  try { await discovery._fetchViaHolesail(VALID_HOLESAIL_KEY) } catch (err) { failure = err }
  t.is(failure?.code, 'HOLESAIL_START_TEARDOWN_FAILED')
  t.ok(/connect timeout/.test(failure?.startCause?.message))
  t.is(failure?.teardownCause?.message, 'injected holesail destroy failure')
  t.is(discovery._holesailClients.get(VALID_HOLESAIL_KEY)?.client, client)
  rejectDestroy = false
  await discovery._destroyHolesailEntry(VALID_HOLESAIL_KEY, discovery._holesailClients.get(VALID_HOLESAIL_KEY))
  t.is(destroys, 2)
  t.absent(discovery._holesailClients.has(VALID_HOLESAIL_KEY))
})

test('network discovery serializes concurrent holesail allocation below hard cap', async (t) => {
  let live = 0
  let maxLive = 0
  const discovery = new NetworkDiscovery({
    holesailClientFactory: () => {
      live++
      maxLive = Math.max(maxLive, live)
      return {
        state: 'connecting',
        connect (_opts, done) { this.state = 'connected'; queueMicrotask(done) },
        async destroy () { if (this.state !== 'destroyed') live--; this.state = 'destroyed' }
      }
    }
  })
  discovery._acceptingWork = true
  discovery._lifecycleEpoch = 1
  discovery._fetchApi = async () => ({ ok: true })
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
  const keys = Array.from({ length: 25 }, (_, index) =>
    'y'.repeat(50) + alphabet[index % alphabet.length] + alphabet[(index + 1) % alphabet.length])
  await Promise.all(keys.map(key => discovery._fetchViaHolesail(key)))
  t.is(discovery._holesailClients.size, 20)
  t.ok(maxLive <= 20, `max live clients stayed bounded (${maxLive})`)
  await discovery.stop()
  t.is(live, 0)
})

test('network discovery stale probe cannot mutate a later lifecycle epoch', async (t) => {
  const pubkey = 'e'.repeat(64)
  const relay = { publicKey: pubkey, holesailKey: null }
  const connection = {}
  const discovery = new NetworkDiscovery()
  discovery._acceptingWork = true
  discovery._lifecycleEpoch = 4
  discovery._relays.set(pubkey, relay)
  discovery._connections.set(pubkey, connection)
  let resolveFetch = null
  discovery._fetchApi = () => new Promise(resolve => { resolveFetch = resolve })
  const probe = discovery._probeApiPort(pubkey, '127.0.0.1', connection, 4)
  await new Promise(resolve => setTimeout(resolve, 0))
  discovery._acceptingWork = false
  discovery._lifecycleEpoch = 5
  resolveFetch({ publicKey: pubkey })
  await probe
  t.absent(relay.apiPort, 'old probe result is discarded')
})
