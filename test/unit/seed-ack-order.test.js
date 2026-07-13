import test from 'brittle'
import b4a from 'b4a'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { BareRelay } from '../../packages/core/core/relay-node/bare-relay.js'

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

function nodeHarness ({ appPromise, corePromise, events }) {
  return {
    config: { regions: ['test'], acceptMode: 'open' },
    seeder: {
      cores: new Map(),
      async seedCore () {
        events.push('core-start')
        return corePromise
      },
      async unseedCore () { events.push('core-rollback') }
    },
    swarm: { keyPair: { publicKey: b4a.alloc(32, 3) } },
    _seedProtocol: protocol(events),
    _resolveAcceptMode: () => 'open',
    _decideAcceptance: () => 'accept',
    _storageAdmission: () => ({ allowed: true, availableBytes: STORAGE_BOUND }),
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

function bareHarness ({ appPromise, corePromise, events }) {
  return {
    config: { enableSeeding: true, regions: ['test'], acceptMode: 'open', acceptAllowlist: [] },
    seeder: {
      cores: new Map(),
      async seedCore () {
        events.push('core-start')
        return corePromise
      },
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
    emit (name) { events.push('emit:' + name) }
  }
}

for (const runtime of [
  { name: 'Node', handler: RelayNode.prototype._onSeedRequest, harness: nodeHarness },
  { name: 'Bare', handler: BareRelay.prototype._onSeedRequest, harness: bareHarness }
]) {
  test(`${runtime.name} seed ACK follows durable drive and extra-core completion`, async (t) => {
    const events = []
    const app = deferred()
    const core = deferred()
    const extraCore = b4a.alloc(32, 4)
    const relay = runtime.harness({ appPromise: app.promise, corePromise: core.promise, events })

    const pending = runtime.handler.call(relay, message({ discoveryKeys: [extraCore] }), {})
    t.alike(events, ['app-start'])

    app.resolve({ alreadySeeded: false })
    await turn()
    t.alike(events, ['app-start', 'core-start'])
    t.absent(events.find(event => event === 'accept'), 'drive persistence alone cannot ACK the full request')

    core.resolve({})
    await pending
    const acceptIndex = events.indexOf('accept')
    t.ok(acceptIndex > events.indexOf('core-start'))
    t.is(events[acceptIndex + 1], 'emit:seed-accepted', 'success is emitted only after the wire ACK')
  })

  test(`${runtime.name} seed durability failure denies without a false ACK`, async (t) => {
    const events = []
    const app = Promise.resolve({ alreadySeeded: false })
    const failure = new Error('injected durable core persistence failure')
    const core = Promise.reject(failure)
    // The handler attaches its rejection path in the same turn.
    core.catch(() => {})
    const relay = runtime.harness({ appPromise: app, corePromise: core, events })

    await runtime.handler.call(relay, message({ discoveryKeys: [b4a.alloc(32, 5)] }), {})

    t.absent(events.find(event => event === 'accept'))
    t.ok(events.includes('app-rollback'), 'partially accepted drive is durably rolled back')
    t.ok(events.includes('deny:storage-admission-blocked'))
    t.ok(events.indexOf('app-rollback') < events.indexOf('deny:storage-admission-blocked'), 'rollback finishes before denial')
  })

  test(`${runtime.name} post-ACK observer failure cannot revoke durable acceptance`, async (t) => {
    const events = []
    const relay = runtime.harness({
      appPromise: Promise.resolve({ alreadySeeded: false }),
      corePromise: Promise.resolve({}),
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
