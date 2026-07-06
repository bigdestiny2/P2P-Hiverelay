/**
 * STO-005 wiring: the relay's periodic disk-pressure loop drives the
 * shard-store's evictUnderPressure().
 *
 * The EvictionManager sweeps app DRIVES; the shard-store owns a dedicated
 * hypercore that path never touches. Unless the relay drives the shard-store's
 * own eviction on the disk-pressure cadence, a filling box leaks shard bytes.
 * These tests prove the relay-node hook exists and passes the live disk reading.
 */
import test from 'brittle'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

function tmpStorage () {
  return path.join(tmpdir(), 'hiverelay-shard-evict-wiring-' + randomBytes(8).toString('hex'))
}

// A minimal shard-store provider stub that records evictUnderPressure calls.
function fakeShardProvider (impl) {
  const calls = []
  return {
    calls,
    provider: {
      async evictUnderPressure (args) {
        calls.push(args)
        return impl ? impl(args) : { ok: true, evicted: 0, expiredEvicted: 0, forcedEvicted: 0, tombstones: [] }
      }
    }
  }
}

function bareNode () {
  return new RelayNode({ storage: tmpStorage(), enableAPI: false })
}

test('STO-005 wiring: _sweepShardStoreUnderPressure passes the live disk usedPct to the shard-store', async (t) => {
  const node = bareNode()
  const shard = fakeShardProvider(() => ({ ok: true, evicted: 2, expiredEvicted: 2, forcedEvicted: 0, tombstones: [] }))
  node.serviceRegistry = { services: new Map([['shard-store', { provider: shard.provider }]]) }
  node.diskMonitor = { getInfo: () => ({ usedPct: 91, totalBytes: 1e9 }) }

  const events = []
  node.on('shard-eviction', (e) => events.push(e))

  await node._sweepShardStoreUnderPressure()
  t.is(shard.calls.length, 1, 'shard-store evictUnderPressure invoked once')
  t.is(shard.calls[0].usedPct, 91, 'live disk usedPct forwarded to the shard-store')
  t.is(events.length, 1, 'a shard-eviction event is emitted when shards were shed')
  t.is(events[0].evicted, 2)
})

test('STO-005 wiring: no shard-store service -> no-op', async (t) => {
  const node = bareNode()
  node.serviceRegistry = { services: new Map() } // shard-store not enabled
  node.diskMonitor = { getInfo: () => ({ usedPct: 99 }) }
  await node._sweepShardStoreUnderPressure() // must not throw
  t.pass('no shard-store service is a clean no-op')
})

test('STO-005 wiring: a missing/absent disk signal is a safe no-op (no eviction call)', async (t) => {
  const node = bareNode()
  const shard = fakeShardProvider()
  node.serviceRegistry = { services: new Map([['shard-store', { provider: shard.provider }]]) }
  node.diskMonitor = { getInfo: () => null } // startup window: no reading yet
  await node._sweepShardStoreUnderPressure()
  t.is(shard.calls.length, 0, 'no eviction attempted without a disk reading')
})

test('STO-005 wiring: a throwing shard eviction cannot crash the loop (best-effort)', async (t) => {
  const node = bareNode()
  const shard = {
    provider: { async evictUnderPressure () { throw new Error('disk gone') } }
  }
  node.serviceRegistry = { services: new Map([['shard-store', { provider: shard.provider }]]) }
  node.diskMonitor = { getInfo: () => ({ usedPct: 96 }) }
  const errs = []
  node.on('shard-eviction-error', (e) => errs.push(e))
  await node._sweepShardStoreUnderPressure() // must resolve, not reject
  t.is(errs.length, 1, 'the error is surfaced as an event, not thrown')
  t.is(errs[0].error, 'disk gone')
})

test('STO-005 wiring: the EvictionManager sweep tick drives the shard-store eviction', async (t) => {
  const node = bareNode()
  // Stub the eviction deps so _ensureEviction can construct a real
  // EvictionManager without a running swarm/registry.
  node.swarm = { keyPair: { publicKey: Buffer.alloc(32, 7) } }
  node.appRegistry = { entries: () => [][Symbol.iterator]() }
  node.seedingRegistry = { getRelaysForApp: () => [] }
  node.storageAccounting = { getBytes: () => 0, getSummary: () => ({ totalBytes: 0 }) }
  node.diskMonitor = { getInfo: () => ({ usedPct: 88, totalBytes: 1e9 }) }
  node._replicationHealth = new Map()
  node.config.eviction = { enabled: true }

  // Record that the sweep tick calls through to the shard-store hook.
  let hookCalls = 0
  node._sweepShardStoreUnderPressure = async () => { hookCalls++ }

  node._ensureEviction()
  t.ok(node.eviction, 'eviction manager constructed')

  // Emitting the periodic 'sweep' event must drive the shard-store hook — this
  // is exactly what the real interval timer does on each pass.
  node.eviction.emit('sweep', { usedPct: 88 })
  // The hook is dispatched via _trackFireAndForget; give the microtask queue a tick.
  await Promise.resolve()
  t.is(hookCalls, 1, 'the eviction sweep tick drove the shard-store eviction hook')

  node.eviction.stop()
})
