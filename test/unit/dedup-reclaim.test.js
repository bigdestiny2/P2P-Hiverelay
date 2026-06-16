/**
 * EvictionManager.reclaimSuperseded — single-relay dedup of stale app versions.
 * Durability-critical: dry-run by default, never touches the current version,
 * never reclaims a sacred (archive/custody/lease) entry even when superseded,
 * and uses the proven unseed → tombstone → purge teardown.
 */

import test from 'brittle'
import { EvictionManager } from 'p2p-hiverelay/core/relay-node/eviction.js'

const A = 'a'.repeat(64) // superseded v1 of 'cool'
const B = 'b'.repeat(64) // current v2 of 'cool'
const C = 'c'.repeat(64) // superseded v1 of 'arch' (archive — sacred)
const D = 'd'.repeat(64) // current v2 of 'arch'
const E = 'e'.repeat(64) // superseded v1 of 'cust' (custody — sacred)
const F = 'f'.repeat(64) // current v2 of 'cust'

function harness (entries, byAppId, bytes = {}) {
  const reg = {
    apps: new Map(entries),
    byAppId: new Map(byAppId),
    get (k) { return this.apps.get(k) },
    evictedCalls: [],
    markEvicted (k) { this.evictedCalls.push(k) }
  }
  const unseeds = []
  const purges = []
  const deps = {
    appRegistry: reg,
    seedingRegistry: {},
    storageAccounting: { getBytes: (k) => (k in bytes ? bytes[k] : null) },
    diskMonitor: {},
    getReplicationHealth: () => new Map(),
    myPubkeyHex: 'relay',
    unseed: async (k) => { unseeds.push(k) },
    purgeDrive: async (k) => { purges.push(k) }
  }
  return { ev: new EvictionManager(deps, {}), reg, unseeds, purges }
}

test('dry-run (default) reports superseded but deletes nothing', async (t) => {
  const { ev, unseeds, purges, reg } = harness(
    [[A, { appId: 'cool', type: 'app', version: '1.0.0' }], [B, { appId: 'cool', type: 'app', version: '2.0.0' }]],
    [['cool', B]],
    { [A]: 500, [B]: 600 }
  )
  const r = await ev.reclaimSuperseded()
  t.is(r.dryRun, true)
  t.is(r.reclaimed.length, 1)
  t.is(r.reclaimed[0].appKey, A)
  t.is(r.freedBytes, 500)
  t.alike(unseeds, [], 'no unseed in dry-run')
  t.alike(purges, [], 'no purge in dry-run')
  t.alike(reg.evictedCalls, [], 'no tombstone in dry-run')
})

test('execute reclaims the superseded version via unseed → tombstone → purge', async (t) => {
  const { ev, unseeds, purges, reg } = harness(
    [[A, { appId: 'cool', type: 'app', version: '1.0.0' }], [B, { appId: 'cool', type: 'app', version: '2.0.0' }]],
    [['cool', B]],
    { [A]: 500, [B]: 600 }
  )
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.alike(r.reclaimed.map(x => x.appKey), [A])
  t.is(r.freedBytes, 500)
  t.alike(unseeds, [A], 'unseeded the stale version')
  t.alike(purges, [A], 'purged the stale version cores')
  t.alike(reg.evictedCalls, [A], 'tombstoned so repair cannot re-adopt')
  t.absent(unseeds.includes(B), 'current version never touched')
})

test('NEVER reclaims a sacred superseded entry (archive / custody / lease)', async (t) => {
  const now = Date.now()
  const { ev, unseeds, purges } = harness(
    [
      [C, { appId: 'arch', type: 'app', version: '1.0.0', durability: 1 }], // archive tier
      [D, { appId: 'arch', type: 'app', version: '2.0.0' }],
      [E, { appId: 'cust', type: 'app', version: '1.0.0', custodyIntentId: 'intent-1' }], // custody
      [F, { appId: 'cust', type: 'app', version: '2.0.0' }],
      [A, { appId: 'lease', type: 'app', version: '1.0.0', leaseManaged: true, retainUntil: now + 1e6 }], // active lease
      [B, { appId: 'lease', type: 'app', version: '2.0.0' }]
    ],
    [['arch', D], ['cust', F], ['lease', B]],
    { [C]: 1, [E]: 1, [A]: 1 }
  )
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0, 'nothing reclaimed — all superseded are sacred')
  t.alike(unseeds, [], 'no sacred entry unseeded')
  t.alike(purges, [], 'no sacred entry purged')
  const reasons = r.skipped.map(s => s.reason).sort()
  t.alike(reasons, ['ARCHIVE_TIER', 'CUSTODY_BOUND', 'LEASE_BOUND'])
})

test('retainVersions keeps the N newest superseded versions per appId', async (t) => {
  // three versions resident: v1(A), v2(C), v3(B-current). superseded = {A,C}.
  const { ev, unseeds } = harness(
    [
      [A, { appId: 'cool', type: 'app', version: '1.0.0' }],
      [C, { appId: 'cool', type: 'app', version: '2.0.0' }],
      [B, { appId: 'cool', type: 'app', version: '3.0.0' }]
    ],
    [['cool', B]],
    { [A]: 100, [C]: 200, [B]: 300 }
  )
  const r = await ev.reclaimSuperseded({ dryRun: false, retainVersions: 1 })
  // keep the newest superseded (v2/C), reclaim the older (v1/A)
  t.alike(r.reclaimed.map(x => x.appKey), [A])
  t.alike(unseeds, [A])
})

test('no superseded versions → nothing reclaimed', async (t) => {
  const { ev } = harness(
    [[A, { appId: 'one', type: 'app' }], [B, { appId: 'two', type: 'app' }]],
    [['one', A], ['two', B]],
    { [A]: 100, [B]: 200 }
  )
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0)
  t.is(r.freedBytes, 0)
})
