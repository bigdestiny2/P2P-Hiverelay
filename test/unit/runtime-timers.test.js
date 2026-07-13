import test from 'brittle'
import b4a from 'b4a'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { PubSub } from 'p2p-hiverelay/core/router/pubsub.js'
import { CircuitRelay } from 'p2p-hiverelay/core/protocol/relay-circuit.js'
import { TokenBucketRateLimiter } from 'p2p-hiverelay/core/protocol/rate-limiter.js'
import { SeedProtocol } from 'p2p-hiverelay/core/protocol/seed-request.js'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'

test('runtime cleanup timers do not keep short-lived processes alive', async (t) => {
  const pubsub = new PubSub()
  const circuit = new CircuitRelay(null, null)
  const limiter = new TokenBucketRateLimiter()
  const seed = new SeedProtocol(null)

  t.absent(pubsub._cleanupInterval.hasRef(), 'pubsub cleanup interval is unrefed')
  t.absent(circuit._cleanupInterval.hasRef(), 'circuit cleanup interval is unrefed')
  t.absent(limiter._cleanupInterval.hasRef(), 'rate limiter cleanup interval is unrefed')
  t.absent(seed._pendingCleanup.hasRef(), 'seed pending cleanup interval is unrefed')
  t.absent(seed._unseedNonceCleanup.hasRef(), 'seed nonce cleanup interval is unrefed')
  t.absent(seed.rateLimiter._cleanupInterval.hasRef(), 'seed rate limiter cleanup interval is unrefed')

  pubsub.destroy()
  circuit.destroy()
  limiter.destroy()
  seed.destroy()
})

test('seeder reannounce interval does not pin the process', async (t) => {
  const keyHex = 'a'.repeat(64)
  const dir = await mkdtemp(join(tmpdir(), 'runtime-timer-seeder-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  let updateCalls = 0
  let refreshStartedResolve
  let refreshResolve
  const refreshStarted = new Promise(resolve => { refreshStartedResolve = resolve })
  const refreshGate = new Promise(resolve => { refreshResolve = resolve })
  const snapshots = []
  const core = {
    discoveryKey: b4a.alloc(32, 0x11),
    fork: 0,
    length: 0,
    byteLength: 0,
    async ready () {},
    async update () {
      updateCalls++
      if (updateCalls === 1) return true
      refreshStartedResolve()
      await refreshGate
      return true
    },
    snapshot () {
      const range = {
        destroyed: false,
        async done () {},
        destroy () { this.destroyed = true }
      }
      const snap = {
        fork: core.fork,
        length: core.length,
        byteLength: core.byteLength,
        closed: false,
        async ready () {},
        download () { return range },
        async close () { this.closed = true },
        range
      }
      snapshots.push(snap)
      return snap
    },
    download () { return { done: async () => {}, destroy () {} } },
    on () {},
    removeListener () {},
    async close () {}
  }
  const store = {
    get () { return core }
  }
  const swarm = {
    join () {},
    async leave () {}
  }
  const admission = {
    reserve: (key, bytes) => ({ allowed: true, key, bytes }),
    owns: () => true,
    commit: () => true,
    rollback: () => true,
    release: () => true,
    markRecoveryReady () {},
    admission: () => ({ allowed: true }),
    failClosed () {}
  }
  const seeder = new Seeder(store, swarm, {
    storagePath: join(dir, 'seeded-cores.json'),
    storageAdmission: admission
  })
  await seeder.start()
  const entry = await seeder.seedCore(keyHex, { maxStorageBytes: 1024 * 1024 })

  t.absent(entry.interval.hasRef(), 'seeder reannounce interval is unrefed')

  const previousSnapshot = entry.rangeSnapshot
  const previousRange = entry.range
  const refreshing = seeder._refreshBoundedDownload(entry)
  await refreshStarted
  t.is(entry.rangeSnapshot, previousSnapshot, 'old snapshot stays live while the replacement proof is pending')
  t.is(entry.range, previousRange, 'old finite range stays live while the replacement proof is pending')
  t.absent(previousSnapshot.closed)
  t.absent(previousRange.destroyed)

  refreshResolve()
  t.ok(await refreshing, 'replacement proof settles')
  t.not(entry.rangeSnapshot, previousSnapshot, 'settled proof installs a fresh pinned snapshot')
  t.not(entry.range, previousRange, 'settled proof installs a fresh finite range')
  t.ok(previousSnapshot.closed, 'previous snapshot closes after replacement')
  t.ok(previousRange.destroyed, 'previous range destroys after replacement')
  t.is(snapshots.length, 2, 'one initial and one replacement snapshot were created')

  await seeder.stop()
})
