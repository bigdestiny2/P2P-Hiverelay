/**
 * Dedup duplication report — read-only estimate of reclaimable bytes from
 * superseded versions still resident on disk. Blind-safe (appId/appKey only).
 */

import test from 'brittle'
import { buildDedupReport } from 'p2p-hiverelay/core/relay-node/dedup-report.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)

// Minimal AppRegistry stand-in: apps Map (appKey->entry) + byAppId (appId->current appKey).
function fakeRegistry (entries, byAppId) {
  return { apps: new Map(entries), byAppId: new Map(byAppId) }
}
function fakeAccounting (bytesByKey) {
  return { getBytes: (k) => (k in bytesByKey ? bytesByKey[k] : null) }
}

test('reports a superseded version (older appKey, appId now points to newer)', (t) => {
  // appId "cool" had version A, now superseded by B (byAppId -> B). A still resident.
  const reg = fakeRegistry(
    [[A, { appId: 'cool', type: 'app', version: '1.0.0' }], [B, { appId: 'cool', type: 'app', version: '2.0.0' }]],
    [['cool', B]]
  )
  const rep = buildDedupReport(reg, fakeAccounting({ [A]: 500, [B]: 600 }))
  t.is(rep.supersededVersions.count, 1)
  t.is(rep.reclaimableBytes, 500, 'only the superseded A counts')
  t.is(rep.supersededVersions.groups.length, 1)
  t.is(rep.supersededVersions.groups[0].current, B)
  t.alike(rep.supersededVersions.groups[0].superseded, [{ appKey: A, bytes: 500 }])
})

test('the current version is never reported', (t) => {
  const reg = fakeRegistry([[B, { appId: 'cool', type: 'app', version: '2.0.0' }]], [['cool', B]])
  const rep = buildDedupReport(reg, fakeAccounting({ [B]: 600 }))
  t.is(rep.supersededVersions.count, 0)
  t.is(rep.reclaimableBytes, 0)
})

test('blind entries never appear (no content-identity grouping)', (t) => {
  const reg = fakeRegistry(
    [[A, { appId: 'x', type: 'app', blind: true, version: '1.0.0' }], [B, { appId: 'x', type: 'app', version: '2.0.0' }]],
    [['x', B]]
  )
  const rep = buildDedupReport(reg, fakeAccounting({ [A]: 999, [B]: 10 }))
  t.is(rep.supersededVersions.count, 0, 'blind A is not counted even though appId matches')
  t.is(rep.reclaimableBytes, 0)
})

test('unmeasured superseded entries are a lower bound, not counted', (t) => {
  const reg = fakeRegistry(
    [[A, { appId: 'cool', type: 'app' }], [C, { appId: 'cool', type: 'app' }], [B, { appId: 'cool', type: 'app' }]],
    [['cool', B]]
  )
  const rep = buildDedupReport(reg, fakeAccounting({ [A]: 500 })) // C unmeasured
  t.is(rep.supersededVersions.count, 2, 'A and C are both superseded')
  t.is(rep.reclaimableBytes, 500, 'C (null bytes) not added')
  t.is(rep.supersededVersions.unmeasured, 1)
  t.ok(/lower bound/.test(rep.note))
})

test('no duplicates → empty report, zero reclaimable', (t) => {
  const reg = fakeRegistry(
    [[A, { appId: 'one', type: 'app' }], [B, { appId: 'two', type: 'app' }]],
    [['one', A], ['two', B]]
  )
  const rep = buildDedupReport(reg, fakeAccounting({ [A]: 100, [B]: 200 }))
  t.is(rep.supersededVersions.count, 0)
  t.is(rep.reclaimableBytes, 0)
})

test('works without StorageAccounting (everything unmeasured)', (t) => {
  const reg = fakeRegistry(
    [[A, { appId: 'cool', type: 'app' }], [B, { appId: 'cool', type: 'app' }]],
    [['cool', B]]
  )
  const rep = buildDedupReport(reg, null)
  t.is(rep.supersededVersions.count, 1)
  t.is(rep.reclaimableBytes, 0)
  t.is(rep.supersededVersions.unmeasured, 1)
})
