import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import test from 'brittle'
import b4a from 'b4a'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'
import { StorageAdmissionAuthority } from 'p2p-hiverelay/config/storage-admission-authority.js'
import {
  OUTBOXLOG_OUTBOX_CORE_PREFIX,
  OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  OutboxLogApp
} from '../../packages/services/builtin/outboxlog/index.js'

const A = 'a'.repeat(64)
const STORAGE_BOUND = 4 * 1024 * 1024
const JOURNAL_BOUND = 32 * 1024 * 1024

function createAdmission () {
  return new StorageAdmissionAuthority({ storage: '/mock', maxStorageBytes: 256 * 1024 * 1024 }, {
    recoveryKinds: [],
    getUsedBytes: () => 0,
    getActualBytes: () => 0,
    sampleFilesystem: () => ({
      ok: true,
      checkedAt: Date.now(),
      storagePath: '/mock',
      realpath: '/mock',
      device: '1',
      inode: '1',
      totalBytes: 100 * 1024 * 1024 * 1024,
      freeBytes: 80 * 1024 * 1024 * 1024
    })
  })
}

test('outboxlog app runtime seeder pins partitioned Hypercore cores by key', async (t) => {
  const store = createMockCorestore()
  const swarm = createMockSwarm()
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-seeder-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const admission = createAdmission()
  const seeder = new Seeder(store, swarm, {
    announceInterval: 60 * 60 * 1000,
    storagePath: join(dir, 'seeded-cores.json'),
    storageAdmission: admission
  })
  const seededEvents = []
  seeder.on('seeding-owned-core', event => seededEvents.push(event))
  await seeder.start()

  const app = new OutboxLogApp({ verifyAppend: () => true })
  t.teardown(async () => {
    await app.stop().catch(() => {})
    await seeder.stop().catch(() => {})
  })

  await app.start({
    config: { outboxlog: { journal: 'hypercore-outboxes', maxJournalStorageBytes: JOURNAL_BOUND, seedMaxStorageBytes: STORAGE_BOUND } },
    store,
    node: { id: 'relay-a', seeder, storageAdmission: admission }
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
  t.alike(store.keyGets, [], 'writer-owned cores are never re-opened as remote seed pins')
  t.is(seeder.cores.size, 0, 'writer-owned cores do not consume seeded-core commitments')
  t.is(seeder._ownedAnnouncements.size, 2)
  t.is(seeder._ownedAnnouncements.get(info.index.coreKey).sourceCore, store.core(info.index.name))
  t.is(seeder._ownedAnnouncements.get(info.outboxes[0].coreKey).sourceCore, store.core(info.outboxes[0].name))
  t.alike(seededEvents.map(event => event.publicKeyHex), seeded.map(entry => entry.coreKey))
  t.alike(seeded.map(entry => entry.maxStorageBytes), [JOURNAL_BOUND, JOURNAL_BOUND])
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

test('outboxlog same-process stop and restart withdraws old sessions before rebinding a new handoff', async (t) => {
  const store = createMockCorestore()
  const swarm = createMockSwarm()
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-seeder-restart-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const admission = createAdmission()
  const seeder = new Seeder(store, swarm, {
    announceInterval: 60 * 60 * 1000,
    storagePath: join(dir, 'seeded-cores.json'),
    storageAdmission: admission
  })
  await seeder.start()
  t.teardown(() => seeder.stop().catch(() => {}))
  const config = { outboxlog: { journal: 'hypercore-outboxes', maxJournalStorageBytes: JOURNAL_BOUND, seedMaxStorageBytes: STORAGE_BOUND } }
  const context = { config, store, node: { id: 'relay-a', seeder, storageAdmission: admission } }

  const first = new OutboxLogApp({ verifyAppend: () => true })
  await first.start(context)
  first.create({ appId: A })
  first.append({ appId: A, op: { type: 'post', data: { id: 'p1', body: 'restart' } } })
  await first.seedPersistenceCores()
  const oldEntries = [...seeder._ownedAnnouncements.values()]
  const oldHandoff = oldEntries[0].handoff
  t.is(oldEntries.length, 2)

  await first.stop()
  t.is(seeder._ownedAnnouncements.size, 0, 'service stop withdraws every owned announcement')
  t.is(swarm.leaves.length, 2, 'old discovery joins are left before authority release')
  t.ok(oldEntries.every(entry => entry.core.closed === true), 'old seeder sessions are closed')
  t.is(admission.validateOwnedHandoff(oldHandoff), false, 'old handoff is released only after withdrawal')

  const second = new OutboxLogApp({ verifyAppend: () => true })
  await second.start(context)
  const rebound = [...seeder._ownedAnnouncements.values()]
  t.is(rebound.length, 2)
  t.ok(rebound.every(entry => entry.handoff !== oldHandoff), 'restart binds the new exclusive handoff')
  t.ok(rebound.every(entry => entry.core.closed === false), 'new sessions are live')
  t.is(swarm.joins.length, 4, 'both cores are actively rejoined')

  await second.stop()
  t.is(seeder._ownedAnnouncements.size, 0)
  t.is(swarm.leaves.length, 4)
})

function createMockCorestore () {
  const coresByName = new Map()
  const coresByKey = new Map()
  const keyGets = []
  return {
    keyGets,
    get ({ name, key, createIfMissing = true }) {
      if (name) {
        if (createIfMissing === false && !coresByName.has(name)) {
          return {
            async ready () {
              const err = new Error('no stored core')
              err.code = 'STORAGE_EMPTY'
              throw err
            },
            async close () {}
          }
        }
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
    this._userData = new Map()
    this.sessions = []
    this.closed = false
    this.writable = true
  }

  get length () {
    return this._blocks.length
  }

  get byteLength () {
    return this._blocks.reduce((total, block) => total + block.byteLength, 0)
  }

  async ready () {}

  session () {
    const session = {
      key: this.key,
      discoveryKey: this.discoveryKey,
      writable: this.writable,
      closed: false,
      async ready () {},
      async close () { this.closed = true }
    }
    this.sessions.push(session)
    return session
  }

  async update () { return true }

  async get (index) {
    return this._blocks[index]
  }

  async append (block) {
    this._blocks.push(Buffer.from(block))
  }

  async getUserData (key) {
    return this._userData.get(key) || null
  }

  async setUserData (key, value) {
    this._userData.set(key, Buffer.from(value))
  }

  async info () {
    return {
      storage: {
        oplog: 4096,
        tree: 4096,
        blocks: this.byteLength,
        bitfield: 4096
      }
    }
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
