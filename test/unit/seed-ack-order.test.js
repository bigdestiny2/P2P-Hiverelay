import test from 'brittle'
import b4a from 'b4a'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { BareRelay } from '../../packages/core/core/relay-node/bare-relay.js'
import { canonicalSeedDiscoveryHint } from '../../packages/core/core/protocol/seed-discovery-hints.js'

const STORAGE_BOUND = 1024 * 1024

function deferred () {
  const state = {}
  const promise = new Promise((resolve, reject) => {
    state.resolve = resolve
    state.reject = reject
  })
  return { promise, ...state }
}

async function turn () {
  await Promise.resolve()
  await Promise.resolve()
}

function message ({ discoveryKeys = [] } = {}) {
  return {
    appKey: b4a.alloc(32, 1),
    publisherPubkey: b4a.alloc(32, 2),
    discoveryKeys,
    replicationFactor: 1,
    maxStorageBytes: STORAGE_BOUND,
    ttlSeconds: 60,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0
  }
}

function protocol (events) {
  return {
    acceptSeedRequest () { events.push('accept') },
    denySeedRequest (channel, appKey, reason) { events.push('deny:' + reason) }
  }
}

function nodeHarness ({ appPromise, events }) {
  return {
    config: { regions: ['test'], acceptMode: 'open' },
    seeder: {
      cores: new Map(),
      async seedCore () { throw new Error('discovery hints are not core keys') },
      async unseedCore () { events.push('core-rollback') }
    },
    swarm: { keyPair: { publicKey: b4a.alloc(32, 3) } },
    _seedProtocol: protocol(events),
    _resolveAcceptMode: () => 'open',
    _decideAcceptance: () => 'accept',
    _storageAdmission: () => ({ allowed: true, availableBytes: STORAGE_BOUND }),
    _informationalAvailableStorageBytes: () => STORAGE_BOUND,
    storageAdmission: { canAcknowledge: () => true },
    leaseManager: null,
    seedingRegistry: null,
    async seedApp () {
      events.push('app-start')
      return appPromise
    },
    async unseedApp () { events.push('app-rollback') },
    emit (name) { events.push('emit:' + name) }
  }
}

function bareHarness ({ appPromise, events }) {
  return {
    config: { enableSeeding: true, regions: ['test'], acceptMode: 'open', acceptAllowlist: [] },
    seeder: {
      cores: new Map(),
      async seedCore () { throw new Error('discovery hints are not core keys') },
      async unseedCore () { events.push('core-rollback') }
    },
    appLifecycle: {
      async seedApp () {
        events.push('app-start')
        return appPromise
      },
      async unseedApp () { events.push('app-rollback') }
    },
    swarm: { keyPair: { publicKey: b4a.alloc(32, 3) } },
    _seedProtocol: protocol(events),
    _storageAdmission: () => ({ allowed: true, availableBytes: STORAGE_BOUND }),
    _informationalAvailableStorageBytes: () => STORAGE_BOUND,
    storageAdmission: { canAcknowledge: () => true },
    emit (name) { events.push('emit:' + name) }
  }
}

for (const runtime of [
  { name: 'Node', handler: RelayNode.prototype._onSeedRequest, harness: nodeHarness },
  { name: 'Bare', handler: BareRelay.prototype._onSeedRequest, harness: bareHarness }
]) {
  test(`${runtime.name} seed ACK follows the one durable drive and never fans out discovery hints`, async (t) => {
    const events = []
    const app = deferred()
    const canonicalHint = canonicalSeedDiscoveryHint(b4a.alloc(32, 1))
    const relay = runtime.harness({ appPromise: app.promise, events })

    const pending = runtime.handler.call(relay, message({ discoveryKeys: [canonicalHint] }), {})
    t.alike(events, ['app-start'])

    app.resolve({ alreadySeeded: false })
    await turn()
    await pending
    const acceptIndex = events.indexOf('accept')
    t.ok(acceptIndex > events.indexOf('app-start'))
    t.absent(events.find(event => event === 'core-start'))
    t.is(events[acceptIndex + 1], 'emit:seed-accepted', 'success is emitted only after the wire ACK')
  })

  test(`${runtime.name} seed durability failure denies without a false ACK`, async (t) => {
    const events = []
    const app = Promise.reject(new Error('injected durable drive persistence failure'))
    const relay = runtime.harness({ appPromise: app, events })

    await runtime.handler.call(relay, message(), {})

    t.absent(events.find(event => event === 'accept'))
    t.absent(events.find(event => event.endsWith('-rollback')), 'seedApp owns reservation rollback internally')
    t.ok(events.includes('deny:storage-admission-blocked'))
  })

  test(`${runtime.name} post-ACK observer failure cannot revoke durable acceptance`, async (t) => {
    const events = []
    const relay = runtime.harness({
      appPromise: Promise.resolve({ alreadySeeded: false }),
      events
    })
    relay.emit = (name) => {
      events.push('emit:' + name)
      if (name === 'seed-accepted') throw new Error('injected observer failure')
    }

    await runtime.handler.call(relay, message(), {})

    t.ok(events.includes('accept'))
    t.absent(events.find(event => event.endsWith('-rollback')))
    t.absent(events.find(event => event.startsWith('deny:')))
  })
}
