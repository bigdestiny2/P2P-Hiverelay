/**
 * EvictionManager.reclaimSuperseded — single-relay dedup of stale app versions.
 * Durability-critical: dry-run by default, supersession decided by VERSION +
 * SAME PUBLISHER (never the byAppId index, never across publishers), never
 * reclaims a sacred (archive/custody/lease) entry, bounds a wedged unseed, and
 * uses the proven unseed → tombstone → purge teardown.
 */

import test from 'brittle'
import { EvictionManager } from '../../packages/core/core/relay-node/eviction.js'

const A = 'a'.repeat(64) // older
const B = 'b'.repeat(64) // newer / current
const C = 'c'.repeat(64)
const D = 'd'.repeat(64)
const E = 'e'.repeat(64)
const F = 'f'.repeat(64)
const PUB = '1'.repeat(64)
const PUB2 = '2'.repeat(64)

function harness (entries, bytes = {}, opts = {}) {
  const reg = {
    apps: new Map(entries),
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
    unseed: opts.unseed || (async (k) => { unseeds.push(k) }),
    purgeDrive: async (k) => { purges.push(k) }
  }
  const cfg = opts.unseedTimeoutMs ? { unseedTimeoutMs: opts.unseedTimeoutMs } : {}
  return { ev: new EvictionManager(deps, cfg), reg, unseeds, purges }
}

const app = (appId, version, extra = {}) => ({ type: 'app', appId, version, publisherPubkey: PUB, ...extra })

test('dry-run (default) reports superseded but deletes nothing', async (t) => {
  const { ev, unseeds, purges, reg } = harness(
    [[A, app('cool', '1.0.0')], [B, app('cool', '2.0.0')]], { [A]: 500, [B]: 600 })
  const r = await ev.reclaimSuperseded()
  t.is(r.dryRun, true)
  t.alike(r.reclaimed.map(x => x.appKey), [A])
  t.is(r.freedBytes, 500)
  t.alike(unseeds, [])
  t.alike(purges, [])
  t.alike(reg.evictedCalls, [])
})

test('execute reclaims the superseded version via unseed → tombstone → purge', async (t) => {
  const { ev, unseeds, purges, reg } = harness(
    [[A, app('cool', '1.0.0')], [B, app('cool', '2.0.0')]], { [A]: 500, [B]: 600 })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.alike(r.reclaimed.map(x => x.appKey), [A])
  t.is(r.freedBytes, 500)
  t.alike(unseeds, [A])
  t.alike(purges, [A])
  t.alike(reg.evictedCalls, [A])
  t.absent(unseeds.includes(B), 'current version never touched')
})

test('DATA-LOSS REGRESSION: older version inserted last is reclaimed, current v2 is NOT', async (t) => {
  const { ev, unseeds } = harness(
    [[B, app('cool', '2.0.0')], [A, app('cool', '1.0.0')]], { [A]: 500, [B]: 600 })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.alike(r.reclaimed.map(x => x.appKey), [A], 'only the older v1 reclaimed')
  t.absent(unseeds.includes(B), 'live v2 never deleted despite being inserted first')
})

test('COLLISION: same appId, different publisher → nothing reclaimed', async (t) => {
  const { ev, unseeds } = harness(
    [[A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB }],
      [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB2 }]],
    { [A]: 500, [B]: 600 })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0, 'unrelated drives colliding on appId are never cross-reclaimed')
  t.alike(unseeds, [])
})

test('NEVER reclaims a sacred superseded entry (archive / custody / lease)', async (t) => {
  const now = Date.now()
  const { ev, unseeds, purges } = harness([
    [C, app('arch', '1.0.0', { durability: 1 })], [D, app('arch', '2.0.0')],
    [E, app('cust', '1.0.0', { custodyIntentId: 'i1' })], [F, app('cust', '2.0.0')],
    [A, app('lease', '1.0.0', { leaseManaged: true, retainUntil: now + 1e6 })], [B, app('lease', '2.0.0')]
  ], { [C]: 1, [E]: 1, [A]: 1 })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0)
  t.alike(unseeds, [])
  t.alike(purges, [])
  t.alike(r.skipped.map(s => s.reason).sort(), ['ARCHIVE_TIER', 'CUSTODY_BOUND', 'LEASE_BOUND'])
})

test('a wedged unseed is bounded — entry skipped, NOT purged or tombstoned', async (t) => {
  const { ev, purges, reg } = harness(
    [[A, app('cool', '1.0.0')], [B, app('cool', '2.0.0')]], { [A]: 500 },
    { unseedTimeoutMs: 50, unseed: () => new Promise(() => {}) /* never resolves */ })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0)
  t.alike(r.skipped, [{ appKey: A, reason: 'unseed-timeout' }])
  t.alike(purges, [], 'purge never runs after unseed timeout')
  t.alike(reg.evictedCalls, [], 'tombstone never written after unseed timeout')
})

test('retainVersions keeps the N newest superseded versions', async (t) => {
  const { ev, unseeds } = harness([
    [A, app('cool', '1.0.0')], [C, app('cool', '2.0.0')], [B, app('cool', '3.0.0')]
  ], { [A]: 100, [C]: 200, [B]: 300 })
  const r = await ev.reclaimSuperseded({ dryRun: false, retainVersions: 1 })
  t.alike(r.reclaimed.map(x => x.appKey), [A], 'keep newest superseded (v2/C), reclaim older (v1/A)')
  t.alike(unseeds, [A])
})

test('signed retainKeys keeps the exact rollback set instead of guessing by count', async (t) => {
  const { ev, unseeds } = harness([
    [A, app('cool', '1.0.0')], [C, app('cool', '2.0.0')], [B, app('cool', '3.0.0')]
  ], { [A]: 100, [C]: 200, [B]: 300 })
  const r = await ev.reclaimSuperseded({ dryRun: false, retainKeys: [A] })
  t.alike(r.reclaimed.map(x => x.appKey), [C], 'exact signed set keeps v1 even though v2 is newer')
  t.alike(unseeds, [C])
})

test('signed release reclamation is scoped to one app and publisher', async (t) => {
  const { ev, unseeds } = harness([
    [A, app('cool', '1.0.0')], [B, app('cool', '2.0.0')],
    [C, app('unrelated', '1.0.0')], [D, app('unrelated', '2.0.0')]
  ], { [A]: 100, [B]: 200, [C]: 300, [D]: 400 })
  const r = await ev.reclaimSuperseded({
    dryRun: false,
    appId: 'cool',
    publisherPubkey: PUB,
    retainKeys: []
  })
  t.alike(r.reclaimed.map(x => x.appKey), [A])
  t.alike(unseeds, [A], 'unrelated superseded app is untouched')
})

test('no superseded versions → nothing reclaimed', async (t) => {
  const { ev } = harness(
    [[A, app('one', '1.0.0')], [B, app('two', '1.0.0')]], { [A]: 100, [B]: 200 })
  const r = await ev.reclaimSuperseded({ dryRun: false })
  t.is(r.reclaimed.length, 0)
  t.is(r.freedBytes, 0)
})
