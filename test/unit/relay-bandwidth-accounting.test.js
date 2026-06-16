import test from 'brittle'
import { Relay } from '../../packages/core/core/relay-node/relay.js'

// Covers the per-frame circuit byte accounting hot path (relay.js):
//  - per-circuit byte cap still enforced
//  - relay-wide bandwidth cap still enforced (check happens before the
//    current frame is added, matching the pre-refactor semantics)
//  - the bucket prune is amortized to at most once per wall-clock second
//    instead of running twice on every data frame
// These pin the behaviour so the prune amortization stays behaviour-preserving.

test('recordCircuitBytes enforces the per-circuit byte cap', async (t) => {
  const relay = new Relay(null, { maxConnections: 10 })
  await relay.start()
  relay.registerCircuit('c1', 'peerA', 100) // 100-byte cap on this circuit
  t.teardown(() => relay.closeCircuit('c1'))

  t.ok(relay.recordCircuitBytes('c1', 60), 'first 60 bytes accepted')
  t.absent(relay.recordCircuitBytes('c1', 60), '60+60 > 100 rejected')
  t.ok(relay.recordCircuitBytes('c1', 30), '60+30 <= 100 still accepted')
  t.is(relay.circuits.get('c1').bytesRelayed, 90, 'rejected frame did not count')
})

test('recordCircuitBytes enforces the relay-wide bandwidth cap', async (t) => {
  const relay = new Relay(null, { maxConnections: 10 })
  await relay.start()
  relay.maxBandwidthBytes = 1000 // tiny window cap for the test
  relay.registerCircuit('c1', 'peerA', 1_000_000_000) // byte cap out of the way
  t.teardown(() => relay.closeCircuit('c1'))

  t.ok(relay.recordCircuitBytes('c1', 600), 'total 0 -> under cap, accepted (now 600)')
  t.ok(relay.recordCircuitBytes('c1', 600), 'total 600 -> under cap, accepted (now 1200)')
  t.absent(relay.recordCircuitBytes('c1', 600), 'total 1200 > 1000 -> rejected')
})

test('recordCircuitBytes rejects unknown circuit', async (t) => {
  const relay = new Relay(null, { maxConnections: 10 })
  await relay.start()
  t.absent(relay.recordCircuitBytes('nope', 10), 'no such circuit')
})

test('_pruneBandwidth drops expired buckets and is amortized within a second', async (t) => {
  const relay = new Relay(null, {})
  await relay.start()
  // Monotonic timestamps — production only ever inserts increasing seconds,
  // which is what lets the prune loop `break` on the first live bucket.
  relay._addBandwidth(100, 1000)
  relay._addBandwidth(100, 1001)
  relay._addBandwidth(100, 1065)
  t.is(relay._bandwidthTotal, 300, 'three buckets recorded')

  // Prune at 1065: cutoff = 1065 - 60 = 1005, so 1000 and 1001 expire.
  relay._pruneBandwidth(1065)
  t.is(relay._bandwidthBuckets.size, 1, 'two expired buckets dropped')
  t.is(relay._bandwidthTotal, 100, 'total reflects only the live bucket')
  t.is(relay._bandwidthLastPruneSec, 1065, 'prune second recorded')

  // Amortization: a second prune within the SAME second must not re-sweep
  // the bucket Map. Spy on iteration to prove the loop body is skipped —
  // this is the per-frame work the refactor removes.
  let sweeps = 0
  const buckets = relay._bandwidthBuckets
  relay._bandwidthBuckets = {
    [Symbol.iterator] () { sweeps++; return buckets[Symbol.iterator]() },
    get size () { return buckets.size },
    get: (k) => buckets.get(k),
    set: (k, v) => buckets.set(k, v),
    delete: (k) => buckets.delete(k)
  }
  relay._pruneBandwidth(1065) // same second -> guarded, no sweep
  t.is(sweeps, 0, 'no re-sweep within the same second')
  relay._pruneBandwidth(1066) // second advances -> sweep runs once
  t.is(sweeps, 1, 'sweep runs once the second advances')
  relay._bandwidthBuckets = buckets
})
