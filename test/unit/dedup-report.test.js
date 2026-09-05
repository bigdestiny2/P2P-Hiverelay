/**
 * Dedup duplication report — read-only estimate of reclaimable bytes from
 * superseded versions still resident on disk.
 *
 * Supersession is decided by VERSION (not the last-writer-wins byAppId index)
 * within a (appId, publisherPubkey) bucket, so an out-of-order boot-replay can
 * never flag the live version as superseded, and an appId collision across
 * different publishers never cross-supersedes. Blind entries never appear.
 */

import test from 'brittle'
import { BoundedDedupReport, buildDedupReport } from 'p2p-hiverelay/core/relay-node/dedup-report.js'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const PUB = '1'.repeat(64)
const PUB2 = '2'.repeat(64)

const reg = (entries) => {
  const registry = new AppRegistry(null)
  for (const [appKey, entry] of entries) registry.set(appKey, entry, { persist: false })
  return registry
}
const acct = (bytes) => ({ getBytes: (k) => (k in bytes ? bytes[k] : null) })
const app = (appId, version, extra = {}) => ({ type: 'app', appId, version, publisherPubkey: PUB, ...extra })

test('superseded = strictly-lower version, same appId + same publisher', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB }],
    [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.count, 1)
  t.is(r.reclaimableBytes, 500)
  t.is(r.supersededVersions.groups[0].current, B, 'current = highest version')
  t.alike(r.supersededVersions.groups[0].superseded, [{ appKey: A, bytes: 500 }])
})

test('DATA-LOSS REGRESSION: older version inserted LAST is still the superseded one', (t) => {
  // Newer (B v2) inserted FIRST, older (A v1) inserted LAST — the order a
  // last-writer-wins byAppId index would get wrong. Version-max must still win.
  const r = buildDedupReport(reg([
    [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB }],
    [A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.groups[0].current, B, 'live v2 is current regardless of insert order')
  t.alike(r.supersededVersions.groups[0].superseded.map(s => s.appKey), [A], 'only the older v1 is superseded')
})

test('COLLISION: same appId, different publisher → never cross-superseded', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB }],
    [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB2 }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.count, 0, 'two publishers colliding on an appId are different apps')
})

test('versionless entries are a TIE → never superseded', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', publisherPubkey: PUB }],
    [B, { type: 'app', appId: 'cool', publisherPubkey: PUB }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.count, 0, 'no version → cannot prove supersession → keep both')
})

test('anonymous entries (no publisherPubkey) are never superseded', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', version: '1.0.0' }],
    [B, { type: 'app', appId: 'cool', version: '2.0.0' }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.count, 0, 'no publisher to prove same-app → skip')
})

test('blind entries never appear (no content-identity grouping, no appKey leak)', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'x', version: '1.0.0', publisherPubkey: PUB, blind: true }],
    [B, { type: 'app', appId: 'x', version: '2.0.0', publisherPubkey: PUB }]
  ]), acct({ [A]: 999, [B]: 10 }))
  t.is(r.supersededVersions.count, 0, 'blind A excluded; bucket has only B → nothing superseded')
  for (const g of r.supersededVersions.groups) t.absent(g.current === A, 'blind appKey never surfaces as current')
})

test('the current (highest) version is never reported', (t) => {
  const r = buildDedupReport(reg([
    [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB }]
  ]), acct({ [B]: 600 }))
  t.is(r.supersededVersions.count, 0)
})

test('unmeasured superseded entries are a lower bound, not counted', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB }],
    [C, { type: 'app', appId: 'cool', version: '1.5.0', publisherPubkey: PUB }],
    [B, { type: 'app', appId: 'cool', version: '2.0.0', publisherPubkey: PUB }]
  ]), acct({ [A]: 500 })) // C unmeasured
  t.is(r.supersededVersions.count, 2, 'A and C are both older than B')
  t.is(r.reclaimableBytes, 500, 'C (null bytes) not added')
  t.is(r.supersededVersions.unmeasured, 1)
  t.ok(/lower bound/.test(r.note))
})

test('bounded report publishes only complete cycles without a full Map iterator', (t) => {
  const registry = new AppRegistry(null)
  const bytes = {}
  const keyFor = (n) => n.toString(16).padStart(64, '0')
  for (let group = 0; group < 65; group++) {
    const older = keyFor(group * 2 + 1)
    const current = keyFor(group * 2 + 2)
    registry.set(older, app(`group-${group}`, '1.0.0'), { persist: false })
    registry.set(current, app(`group-${group}`, '2.0.0'), { persist: false })
    bytes[older] = 1
  }
  registry.apps[Symbol.iterator] = () => { throw new Error('full AppRegistry iterator forbidden') }

  const report = new BoundedDedupReport(registry, acct(bytes), { budget: 64 })
  const first = report.advance()
  t.is(first.examined, 64, 'first turn consumes the exact finite budget')
  t.is(first.complete, false)
  t.is(report.snapshot().supersededVersions.count, 0, 'partial cycle retains prior complete aggregate')

  const second = report.advance()
  t.is(second.examined, 64)
  t.is(second.complete, false)
  t.is(report.snapshot().supersededVersions.count, 0, 'second partial page still cannot publish')

  const terminal = report.advance()
  t.is(terminal.examined, 2)
  t.is(terminal.complete, true)
  t.is(report.snapshot().supersededVersions.count, 65, 'terminal page atomically publishes the full aggregate')
  t.is(report.snapshot().reclaimableBytes, 65)
  t.is(report.snapshot().supersededVersions.groups.length, 64, 'operator detail is independently capped')
  t.is(report.snapshot().supersededVersions.detailTruncated, true)

  report.advance()
  t.is(report.snapshot().supersededVersions.count, 65, 'next-cycle partial work retains the completed view')
  report.stop()
  t.is(registry._appPopulation.consumerCount, 0, 'stop releases the fixed cursor')
})
