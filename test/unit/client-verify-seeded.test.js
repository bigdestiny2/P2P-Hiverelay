/**
 * verifySeeded (Tier 1): trustlessly confirm a relay holds + serves an app.
 * The replication itself is Hypercore's (it verifies every block against the
 * drive key — upstream-tested); here we cover the parts THIS method owns: the
 * argument/connection guards, and the pure verdict logic.
 */
import test from 'brittle'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { EventEmitter } from 'events'
import { randomBytes } from 'crypto'

function mockSwarm () {
  const s = new EventEmitter()
  s.keyPair = { publicKey: Buffer.alloc(32, 0xaa), secretKey: null }
  s.connections = new Set(); s.join = () => ({ destroy () {} })
  s.leave = async () => {}; s.flush = async () => {}; s.destroy = async () => {}
  return s
}
const mockStore = () => ({ close: async () => {}, get: () => ({ key: Buffer.alloc(32), ready: async () => {} }) })
function makeClient () {
  const c = new HiveRelayClient({ swarm: mockSwarm(), store: mockStore() })
  c._started = true
  return c
}
const V = (c, o) => c._seededVerdict({ driveKey: 'x', relay: 'r', metaLength: 10, blobsLength: 5, relayIsPeer: true, relayRemoteLength: 10, contentVerified: true, ...o })

test('verifySeeded guards: requires opts.relay + an active connection (before any replication)', async (t) => {
  const c = makeClient()
  await t.exception(c.verifySeeded('a'.repeat(64), {}), /opts\.relay/)
  await t.exception(c.verifySeeded('a'.repeat(64), { relay: randomBytes(32).toString('hex') }), /NO_RELAY/)
})

test('verdict: relay is a full-length peer AND content verified => complete', (t) => {
  const v = V(makeClient(), {})
  t.ok(v.relayIsPeer); t.ok(v.relayHasFullLength); t.ok(v.contentVerified); t.ok(v.complete)
})

test('verdict: relay behind on length => not full, not complete', (t) => {
  const v = V(makeClient(), { relayRemoteLength: 4 })
  t.absent(v.relayHasFullLength); t.absent(v.complete)
})

test('verdict: relay not a peer => not held', (t) => {
  const v = V(makeClient(), { relayIsPeer: false, relayRemoteLength: 0 })
  t.absent(v.relayIsPeer); t.absent(v.relayHasFullLength); t.absent(v.complete)
})

test('verdict: content not verified => not complete even if relay advertises full', (t) => {
  const v = V(makeClient(), { contentVerified: false })
  t.ok(v.relayHasFullLength); t.absent(v.complete)
})

test('verdict: empty drive (metaLength 0) is never "full"', (t) => {
  const v = V(makeClient(), { metaLength: 0, relayRemoteLength: 0 })
  t.absent(v.relayHasFullLength); t.absent(v.complete)
})
