import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import test from 'brittle'
import b4a from 'b4a'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'
import {
  OUTBOXLOG_OUTBOX_CORE_PREFIX,
  OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  OutboxLogApp
} from '../../packages/services/builtin/outboxlog/index.js'

const A = 'a'.repeat(64)

test('outboxlog app runtime seeder pins partitioned Hypercore cores by key', async (t) => {
  const store = createMockCorestore()
  const swarm = createMockSwarm()
  const seeder = new Seeder(store, swarm, { announceInterval: 60 * 60 * 1000 })
  const seededEvents = []
  seeder.on('seeding-core', event => seededEvents.push(event))
  await seeder.start()

  const app = new OutboxLogApp({ verifyAppend: () => true })
  t.teardown(async () => {
    await app.stop().catch(() => {})
    await seeder.stop().catch(() => {})
  })

  await app.start({
    config: { outboxlog: { journal: 'hypercore-outboxes' } },
    store,
    node: { id: 'relay-a', seeder }
  })
  app.create({ appId: A })
  app.append({ appId: A, op: { type: 'post', data: { id: 'p1', body: 'runtime-seeder-pickup' } } })

  // start() auto-seeds the index core (the only core that exists at start,
  // length 0) to the fleet seeder; this manual re-seed picks up the outbox core
  // created by create()/append() above. seedCore() is idempotent, so the index
  // is not re-pinned (no second seeding-core event for it).
  const seeded = await app.seedPersistenceCores()
  const info = app.journalInfo()

  t.alike(seeded.map(entry => entry.role), ['index', 'outbox'])
  t.alike(seeded.map(entry => entry.name), [
    OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
    OUTBOXLOG_OUTBOX_CORE_PREFIX + A
  ])
  t.alike(seeded.map(entry => entry.coreKey), [info.index.coreKey, info.outboxes[0].coreKey])
  t.alike(store.keyGets, seeded.map(entry => entry.coreKey))
  t.is(seeder.cores.size, 2)
  t.is(seeder.cores.get(info.index.coreKey).core, store.core(info.index.name))
  t.is(seeder.cores.get(info.outboxes[0].coreKey).core, store.core(info.outboxes[0].name))
  t.alike(seededEvents.map(event => event.publicKeyHex), seeded.map(entry => entry.coreKey))
  // Index seeded on start() at length 0 (no outbox exists yet); the outbox is
  // seeded on the manual re-seed, by which point create()+append() have taken
  // its length to 2.
  t.alike(seededEvents.map(event => event.length), [0, 2])
  t.is(swarm.joins.length, 2)
  t.alike(swarm.joins.map(entry => entry.opts), [
    { server: true, client: true },
    { server: true, client: true }
  ])

  await app.stop()
  await seeder.stop()
  t.alike(swarm.leaves.length, 2)
})

function createMockCorestore () {
  const coresByName = new Map()
  const coresByKey = new Map()
  const keyGets = []
  return {
    keyGets,
    get ({ name, key }) {
      if (name) {
        if (!coresByName.has(name)) {
          const core = new MockCore(name)
          coresByName.set(name, core)
          coresByKey.set(b4a.toString(core.key, 'hex'), core)
        }
        return coresByName.get(name)
      }
      const keyHex = b4a.toString(key, 'hex')
      keyGets.push(keyHex)
      return coresByKey.get(keyHex) || new MockCore('remote/' + keyHex)
    },
    core (name) {
      return coresByName.get(name)
    }
  }
}

class MockCore extends EventEmitter {
  constructor (name) {
    super()
    this.name = name
    this.key = createHash('sha256').update(name).digest()
    this.discoveryKey = createHash('sha256').update('discovery:' + name).digest()
    this._blocks = []
    this._downloads = []
    this.closed = false
  }

  get length () {
    return this._blocks.length
  }

  async ready () {}

  async get (index) {
    return this._blocks[index]
  }

  async append (block) {
    this._blocks.push(Buffer.from(block))
  }

  download (opts) {
    const range = {
      opts,
      destroyed: false,
      async done () {},
      destroy () {
        this.destroyed = true
      }
    }
    this._downloads.push(range)
    return range
  }

  async close () {
    this.closed = true
  }
}

function createMockSwarm () {
  return {
    joins: [],
    leaves: [],
    join (topic, opts) {
      this.joins.push({ topic: Buffer.from(topic), opts })
    },
    async leave (topic) {
      this.leaves.push(Buffer.from(topic))
    }
  }
}
