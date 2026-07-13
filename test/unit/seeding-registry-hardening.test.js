import test from 'brittle'
import { randomBytes } from 'crypto'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'

function mockStore () {
  return {
    get () {
      return {
        key: randomBytes(32),
        length: 0,
        async ready () {},
        replicate () {},
        on () {},
        async close () {},
        async get () { return null }
      }
    }
  }
}

function mockSwarm () {
  return {
    keyPair: { publicKey: randomBytes(32) }
  }
}

function registryForStop (events, discoveryHandle) {
  const registry = new SeedingRegistry({}, {
    removeListener (event) { events.push(`swarm-remove-${event}`) }
  })
  registry.running = true
  registry._discoveryHandle = discoveryHandle
  registry._onSwarmConnection = () => {}
  registry._onLocalAppend = () => {}
  registry.localLog = {
    removeListener (event) { events.push(`local-remove-${event}`) },
    async close () { events.push('local-close') }
  }
  return registry
}

test('SeedingRegistry - rejects meta announce when declared peer key mismatches transport key', (t) => {
  const registry = new SeedingRegistry(mockStore(), mockSwarm())
  let called = 0
  registry._registerPeerLog = async () => { called++ }

  const transportKey = randomBytes(32)
  registry._onMetaMessage({}, { publicKey: transportKey }, {
    type: 0,
    logKey: 'a'.repeat(64),
    peerPubkey: 'b'.repeat(64)
  })

  t.is(called, 0, 'registry ignores mismatched peer identity claim')
})

test('SeedingRegistry - rejects forged seed-accept relay pubkey attribution', (t) => {
  const registry = new SeedingRegistry(mockStore(), mockSwarm())
  const appKey = 'a'.repeat(64)

  registry._applyEntry({
    type: 'seed-accept',
    timestamp: Date.now(),
    appKey,
    relayPubkey: 'b'.repeat(64),
    region: 'na'
  }, {
    logId: 'deadbeef',
    peerPubkey: 'c'.repeat(64)
  })

  t.is(registry._acceptances.get(appKey), undefined, 'mismatched relay identity not indexed')
})

test('SeedingRegistry - accepts seed-accept when relay identity matches log peer', (t) => {
  const registry = new SeedingRegistry(mockStore(), mockSwarm())
  const appKey = 'a'.repeat(64)
  const relayPubkey = 'd'.repeat(64)

  registry._applyEntry({
    type: 'seed-accept',
    timestamp: Date.now(),
    appKey,
    relayPubkey,
    region: 'na'
  }, {
    logId: 'feedface',
    peerPubkey: relayPubkey
  })

  const acceptances = registry._acceptances.get(appKey)
  t.ok(Array.isArray(acceptances), 'acceptance list created')
  t.is(acceptances.length, 1, 'matching acceptance indexed')
  t.is(acceptances[0].relayPubkey, relayPubkey, 'relay pubkey preserved')
})

test('SeedingRegistry - enforces max peer log cap', async (t) => {
  const registry = new SeedingRegistry(mockStore(), mockSwarm(), { maxPeerLogs: 1 })
  registry.localLog = { key: randomBytes(32) }
  registry._peerLogMeta.set('f'.repeat(64), {
    log: { replicate () {} },
    onAppend: null,
    peerPubkey: '1'.repeat(64)
  })

  await registry._registerPeerLog('a'.repeat(64), '2'.repeat(64), {})
  t.is(registry._peerLogMeta.size, 1, 'new peer log rejected once cap is reached')
})

test('SeedingRegistry - stop awaits its discovery handle before closing logs', async (t) => {
  const events = []
  let settleDiscovery
  const discoverySettled = new Promise(resolve => { settleDiscovery = resolve })
  const registry = registryForStop(events, {
    async destroy () {
      events.push('discovery-destroy-start')
      await discoverySettled
      events.push('discovery-destroy-done')
    }
  })

  const stopping = registry.stop()
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events, [
    'swarm-remove-connection',
    'local-remove-append',
    'discovery-destroy-start'
  ])
  t.ok(registry.localLog, 'registry log remains open while discovery retirement is pending')

  settleDiscovery()
  await stopping
  t.alike(events.slice(-3), ['discovery-destroy-start', 'discovery-destroy-done', 'local-close'])
  t.is(registry._discoveryHandle, null)
  t.is(registry.localLog, null)
  t.is(registry._stopping, false)
})

test('SeedingRegistry - rejected discovery retirement retains handle and logs for retry', async (t) => {
  const events = []
  let rejectDestroy = true
  const handle = {
    async destroy () {
      events.push('discovery-destroy')
      if (rejectDestroy) throw new Error('injected registry discovery failure')
    }
  }
  const registry = registryForStop(events, handle)

  await t.exception(registry.stop(), /injected registry discovery failure/)
  t.is(registry._discoveryHandle, handle)
  t.ok(registry.localLog, 'registry log remains owned after failed discovery retirement')
  t.is(registry._stopping, true)
  t.absent(events.includes('local-close'))

  rejectDestroy = false
  await registry.stop()
  t.is(registry._discoveryHandle, null)
  t.is(registry.localLog, null)
  t.is(registry._stopping, false)
  t.ok(events.includes('local-close'))
})
