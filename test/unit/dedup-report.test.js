/**
 * Dedup duplication report — read-only estimate of reclaimable bytes from
 * superseded versions still resident on disk.
 *
 * Supersession is decided by signed release sequence when present, otherwise
 * VERSION (never the last-writer-wins byAppId index)
 * within a (appId, publisherPubkey) bucket, so an out-of-order boot-replay can
 * never flag the live version as superseded, and an appId collision across
 * different publishers never cross-supersedes. Blind entries never appear.
 */

import test from 'brittle'
import { buildDedupReport } from '../../packages/core/core/relay-node/dedup-report.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const PUB = '1'.repeat(64)
const PUB2 = '2'.repeat(64)

// Report reads ONLY appRegistry.apps now (never byAppId).
const reg = (entries) => ({ apps: new Map(entries) })
const acct = (bytes) => ({ getBytes: (k) => (k in bytes ? bytes[k] : null) })

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

test('signed release sequence supersedes drives even when semver is unchanged', (t) => {
  const r = buildDedupReport(reg([
    [A, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB, release: { sequence: 4 } }],
    [B, { type: 'app', appId: 'cool', version: '1.0.0', publisherPubkey: PUB, release: { sequence: 5 } }]
  ]), acct({ [A]: 500, [B]: 600 }))
  t.is(r.supersededVersions.groups[0].current, B)
  t.alike(r.supersededVersions.groups[0].superseded, [{ appKey: A, bytes: 500 }])
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
