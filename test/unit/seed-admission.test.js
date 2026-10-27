/**
 * Bounded seed admission (v0.24.5) — RelayNode._onSeedRequest.
 *
 * Production bug (2026-10-26): the capacity check covered the app only;
 * every extra `discoveryKeys` core (PearTube's per-video blob cores) was
 * pinned via seeder.seedCore with no bound and no capacity check, so disks
 * filled to 100%. Now the request's maxStorageBytes is an aggregate budget
 * for the app plus its extra cores: it must fit the relay's real free
 * capacity (cap AND a physical-disk reserve) or the request is denied with
 * the existing `insufficient-storage` wire deny, and each extra core is
 * pinned bounded by it in the app's budget group.
 *
 * Same in-process pattern as relay-node.test.js: a constructed (not
 * started) RelayNode with a fake seed protocol, and a real Seeder over a
 * fake corestore so reservations are the production code's.
 */

import test from 'brittle'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import sodium from 'sodium-universal'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'

const GiB = 1024 * 1024 * 1024
const MiB = 1024 * 1024

function tmpStorage () {
  return path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex'))
}

function discoveryKey (publicKey) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from('hypercore'), publicKey)
  return out
}

function fakeStore () {
  return {
    get ({ key }) {
      return {
        key,
        discoveryKey: b4a.alloc(32, 9),
        length: 0,
        byteLength: 0,
        async ready () {},
        async info () { return { length: 0, byteLength: 0, contiguousLength: 0, storage: null } },
        download () { return { done: () => new Promise(() => {}), destroy () {} } },
        on () {},
        async close () {}
      }
    }
  }
}

function makeNode (t, { cap = 10 * GiB, disk = null } = {}) {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node.config.maxStorageBytes = cap
  node.config.acceptMode = 'open'
  node.swarm = { keyPair: { publicKey: randomBytes(32) } }
  if (disk) node.diskMonitor = { criticalThreshold: 95, getInfo: () => disk }

  const sent = { accepts: [], denies: [], seededApps: [], seedCalls: [] }
  node._seedProtocol = {
    acceptSeedRequest (appKey, relayPk, region, availableBytes) { sent.accepts.push({ appKey, availableBytes }) },
    denySeedRequest (channel, appKey, reasonCode, detail) { sent.denies.push({ reasonCode, detail }) }
  }
  node.seedApp = async (key) => { sent.seededApps.push(key) }

  node.seeder = new Seeder(fakeStore(), { join () {}, async leave () {} }, {
    maxStorageBytes: cap,
    getAvailableBytes: () => node._availableStorageBytes()
  })
  const realSeedCore = node.seeder.seedCore.bind(node.seeder)
  node.seeder.seedCore = (key, opts) => {
    sent.seedCalls.push({ key, opts })
    return realSeedCore(key, opts)
  }
  t.teardown(() => node.seeder.stop())
  return { node, sent }
}

function request ({ appKey = randomBytes(32), maxStorageBytes, discoveryKeys = [] } = {}) {
  return {
    appKey,
    publisherPubkey: randomBytes(32),
    discoveryKeys,
    replicationFactor: 2,
    maxStorageBytes,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0
  }
}

const channel = {} // deny() only needs a truthy channel; the fake protocol records it

test('admission: app + extra cores over the free capacity -> insufficient-storage deny', async (t) => {
  const { node, sent } = makeNode(t, { cap: 1 * GiB })
  node._onSeedRequest(request({ maxStorageBytes: 2 * GiB, discoveryKeys: [randomBytes(32), randomBytes(32)] }), channel)

  t.is(sent.denies.length, 1, 'denied on the wire so the publisher moves on')
  t.is(sent.denies[0].reasonCode, 'insufficient-storage', 'existing deny reason')
  t.ok(sent.denies[0].detail.includes('(app + 2 cores)'), 'detail names the request shape')
  t.is(sent.accepts.length, 0)
  t.is(sent.seededApps.length, 0, 'app not seeded')
  t.is(sent.seedCalls.length, 0, 'no core pinned')
})

test('admission: extra cores are pinned bounded by the request budget, in the app group', async (t) => {
  const { node, sent } = makeNode(t, { cap: 10 * GiB })
  const appKey = randomBytes(32)
  const appHex = b4a.toString(appKey, 'hex')
  const v1 = randomBytes(32)
  const v2 = randomBytes(32)
  // Standard SDK requests list the app's own discovery key; PearTube adds
  // per-video cores (one duplicated here).
  node._onSeedRequest(request({ appKey, maxStorageBytes: 3 * GiB, discoveryKeys: [discoveryKey(appKey), v1, v2, v1, appKey] }), channel)

  t.is(sent.denies.length, 0)
  t.is(sent.accepts.length, 1)
  t.alike(sent.seededApps, [appHex])
  t.alike(sent.seedCalls.map(c => c.key), [b4a.toString(v1, 'hex'), b4a.toString(v2, 'hex')],
    'app key, app discovery key (a topic, not a core) and duplicates are not pinned')
  for (const c of sent.seedCalls) {
    t.alike(c.opts, { maxStorageBytes: 3 * GiB, group: appHex, source: 'seed-request' }, 'request budget passed as the bound')
  }
  t.is(node.seeder.pendingBytes(), 3 * GiB, 'budget reserved once for the whole request, synchronously')
  t.is(node._storageUsedBytes(), 3 * GiB, 'reservation counts as used — the cap binds before bytes land')

  // The reservation binds the next request immediately.
  node._onSeedRequest(request({ maxStorageBytes: 8 * GiB, discoveryKeys: [randomBytes(32)] }), channel)
  t.is(sent.denies.length, 1)
  t.is(sent.denies[0].reasonCode, 'insufficient-storage', '3 GiB reserved + 8 GiB > 10 GiB cap')
})

test('admission: physical-disk reserve binds even when the cap has room', async (t) => {
  // 100 GiB volume with 10 GiB free; default reserve = (100 - 95)% = 5 GiB,
  // so only 5 GiB is admissible although the cap allows 50.
  const disk = { usedPct: 90, freeBytes: 10 * GiB, totalBytes: 100 * GiB }
  const { node, sent } = makeNode(t, { cap: 50 * GiB, disk })
  t.is(node._availableStorageBytes(), 5 * GiB)

  node._onSeedRequest(request({ maxStorageBytes: 6 * GiB, discoveryKeys: [randomBytes(32)] }), channel)
  t.is(sent.denies.length, 1)
  t.is(sent.denies[0].reasonCode, 'insufficient-storage', 'would breach the disk reserve')

  node._onSeedRequest(request({ maxStorageBytes: 4 * GiB, discoveryKeys: [randomBytes(32)] }), channel)
  t.is(sent.denies.length, 1, 'fits inside the reserve')
  t.is(sent.accepts.length, 1)

  // Operator override of the reserve.
  node.config.seedDiskReserveBytes = 0
  t.is(node._availableStorageBytes(), 10 * GiB - 4 * GiB, 'free disk minus the outstanding reservation')
})

test('admission: a full relay refuses even budget-less requests', async (t) => {
  const disk = { usedPct: 97, freeBytes: 3 * GiB, totalBytes: 100 * GiB } // inside the 5% reserve
  const { node, sent } = makeNode(t, { cap: 50 * GiB, disk })
  node._onSeedRequest(request({ maxStorageBytes: 0 }), channel)
  t.is(sent.denies.length, 1)
  t.is(sent.denies[0].reasonCode, 'insufficient-storage')
  t.is(sent.seededApps.length, 0)
})

test('admission: extra cores with no declared budget get the SDK default (1 GiB) bound', async (t) => {
  const { node, sent } = makeNode(t, { cap: 10 * GiB })
  node._onSeedRequest(request({ maxStorageBytes: 0, discoveryKeys: [randomBytes(32)] }), channel)
  t.is(sent.denies.length, 0)
  t.is(sent.seedCalls.length, 1)
  t.is(sent.seedCalls[0].opts.maxStorageBytes, 1 * GiB, 'never an unbounded pin')
})

test('admission: an app-only request keeps the legacy semantics', async (t) => {
  const { node, sent } = makeNode(t, { cap: 1 * GiB })
  node._onSeedRequest(request({ maxStorageBytes: 512 * MiB, discoveryKeys: [] }), channel)
  t.is(sent.denies.length, 0)
  t.is(sent.seededApps.length, 1)
  t.is(sent.seedCalls.length, 0)
  t.is(node.seeder.pendingBytes(), 0, 'no bare-core reservation for an app-only request')
})

test('admission: re-affirming an already-held app + pinned cores is not denied', async (t) => {
  const { node, sent } = makeNode(t, { cap: 4 * GiB })
  const appKey = randomBytes(32)
  const v1 = randomBytes(32)
  node._onSeedRequest(request({ appKey, maxStorageBytes: 3 * GiB, discoveryKeys: [v1] }), channel)
  await new Promise((resolve) => setImmediate(resolve))
  t.ok(node.seeder.cores.has(b4a.toString(v1, 'hex')), 'pinned')
  node.seededApps.set(b4a.toString(appKey, 'hex'), { startedAt: Date.now() })

  // Its own 3 GiB reservation leaves 1 GiB — re-checking the 3 GiB budget
  // would deny a request this relay is already serving.
  node._onSeedRequest(request({ appKey, maxStorageBytes: 3 * GiB, discoveryKeys: [v1] }), channel)
  t.is(sent.denies.length, 0)
  t.is(sent.accepts.length, 2)
})
