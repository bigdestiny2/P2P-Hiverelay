/**
 * catalogForBroadcast() must collapse app-type rows by appId (keep latest
 * version), matching the HTTP catalog() view — the P2P broadcast previously
 * leaked superseded versions to peers. Redacted (appId null) + non-app rows
 * pass through.
 */

import test from 'brittle'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const D = 'd'.repeat(64)
const E = 'e'.repeat(64)
const PUBLISHER_A = '1'.repeat(64)
const PUBLISHER_B = '2'.repeat(64)

test('catalogForBroadcast collapses app versions by appId (keep latest)', (t) => {
  const r = new AppRegistry(null)
  r.set(A, { type: 'app', appId: 'cool', version: '1.0.0' })
  r.set(B, { type: 'app', appId: 'cool', version: '2.0.0' })

  const bc = r.catalogForBroadcast()
  const cool = bc.filter(x => x.type === 'app' && x.appId === 'cool')
  t.is(cool.length, 1, 'one broadcast row for appId cool')
  t.is(cool[0].version, '2.0.0', 'highest version kept')
  t.is(cool[0].appKey, B, 'the latest entry survives')

  // catalog() already dedups — regression guard that both views agree.
  const httpCool = r.catalog().filter(x => x.type === 'app' && x.id === 'cool')
  t.is(httpCool.length, 1)
  t.is(httpCool[0].version, '2.0.0')
})

test('non-app types and distinct appIds are never collapsed', (t) => {
  const r = new AppRegistry(null)
  r.set(A, { type: 'app', appId: 'one', version: '1.0.0' })
  r.set(B, { type: 'app', appId: 'two', version: '1.0.0' })
  r.set(D, { type: 'drive', appId: 'one' }) // same appId but a drive — not collapsed
  r.set(E, { type: 'dataset' })

  const bc = r.catalogForBroadcast()
  t.is(bc.filter(x => x.type === 'app').length, 2, 'both distinct apps kept')
  t.ok(bc.some(x => x.type === 'drive'), 'drive passes through')
  t.ok(bc.some(x => x.type === 'dataset'), 'dataset passes through')
})

test('blind/redacted rows (appId null) pass through, never collapsed', (t) => {
  const r = new AppRegistry(null)
  r.set(A, { type: 'app', appId: 'x', version: '1.0.0', blind: true, blindContentId: 'f'.repeat(64) })
  r.set(B, { type: 'app', appId: 'x', version: '2.0.0', blind: true, blindContentId: '9'.repeat(64) })

  const bc = r.catalogForBroadcast()
  const blindRows = bc.filter(x => x.blind === true)
  t.is(blindRows.length, 2, 'both blind rows survive (appId redacted to null, not collapsed)')
  t.ok(blindRows.every(x => x.appId === null), 'blind rows carry no appId')
})

test('catalog winner index uses canonical SemVer and lowercase appKey tie-breaks', (t) => {
  const r = new AppRegistry(null)
  r.set(B, { type: 'app', appId: 'winner', version: '2.0.0' })
  r.set(A, { type: 'app', appId: 'winner', version: '2.0.0' })
  r.set(C, { type: 'app', appId: 'winner', version: 'not-semver' })
  r.set(D, { type: 'app', appId: 'winner', version: null })
  r.set(E, {
    type: 'app',
    appId: 'winner',
    version: '99.0.0',
    blind: true,
    blindContentId: 'f'.repeat(64)
  })

  t.is(r.catalogWinner('winner').appKey, A, 'valid SemVer wins and equal precedence selects the smaller key')
  t.is(r.catalogForBroadcast().find(row => row.appId === 'winner').appKey, A, 'broadcast uses the same comparator')
  t.is(r.catalog().find(row => row.id === 'winner').appKey, A, 'HTTP projection uses the same comparator')

  r.update(A, { version: 'invalid' })
  t.is(r.catalogWinner('winner').appKey, B, 'updating the winner promotes the next exact candidate')
  r.delete(B)
  t.is(r.catalogWinner('winner').appKey, A, 'both invalid versions tie by lowercase appKey')
  r.delete(A)
  t.is(r.catalogWinner('winner').appKey, C, 'null and invalid versions tie by lowercase appKey')
  t.is(r.catalogForBroadcast().find(row => row.appId === 'winner').appKey, C)
  t.is(r.catalog().find(row => row.id === 'winner').appKey, C, 'HTTP projection preserves null instead of inventing SemVer precedence')
})

test('catalog winner index supports deletion-safe publisher-scoped lookup', (t) => {
  const r = new AppRegistry(null)
  r.set(A, { type: 'app', appId: 'scoped', version: '1.0.0', publisherPubkey: PUBLISHER_A })
  r.set(B, { type: 'app', appId: 'scoped', version: '2.0.0', publisherPubkey: PUBLISHER_A })
  r.set(C, { type: 'app', appId: 'scoped', version: '9.0.0', publisherPubkey: PUBLISHER_B })

  t.is(r.catalogWinner('scoped').appKey, C, 'global catalog winner spans publishers')
  t.is(r.catalogWinner('scoped', PUBLISHER_A.toUpperCase()).appKey, B, 'publisher scope normalizes canonical hex')
  t.is(r.catalogWinner('scoped', PUBLISHER_B).appKey, C)
  t.is(r.catalogWinner('scoped', 'not-a-key'), null, 'invalid publisher scope fails closed')

  r.update(C, { version: 'invalid' })
  t.is(r.catalogWinner('scoped').appKey, B, 'global winner advances without scanning after update')
  r.delete(B)
  t.is(r.catalogWinner('scoped', PUBLISHER_A).appKey, A, 'publisher winner advances after deletion')
})

test('catalog superseded rank is logarithmic and excludes equal-version tiers', (t) => {
  const r = new AppRegistry(null)
  r.set(A, { type: 'app', appId: 'ranked', version: '1.0.0', publisherPubkey: PUBLISHER_A })
  r.set(B, { type: 'app', appId: 'ranked', version: '3.0.0', publisherPubkey: PUBLISHER_A })
  r.set(C, { type: 'app', appId: 'ranked', version: '2.0.0', publisherPubkey: PUBLISHER_A })
  r.set(D, { type: 'app', appId: 'ranked', version: '2.0.0', publisherPubkey: PUBLISHER_A })

  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, A), 2, 'both newer superseded entries rank ahead of v1')
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, C), 0, 'winner tier is excluded from the rank')
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, D), 0, 'equal-version peers do not rank each other')
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, B), null, 'the winner is not superseded')
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_B, A), null, 'publisher mismatch fails closed')

  r.delete(B)
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, C), null, 'equal winner-version peers remain non-superseded')
  t.is(r.catalogSupersededRank('ranked', PUBLISHER_A, A), 0, 'rank advances after deleting the winner tier')
})
