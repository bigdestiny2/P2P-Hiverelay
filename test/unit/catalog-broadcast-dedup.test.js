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
const D = 'd'.repeat(64)
const E = 'e'.repeat(64)

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
