import test from 'brittle'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'anchor-test-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

function appKey (hexDigit) {
  return hexDigit.repeat(64)
}

test('AppRegistry — anchored defaults to false on new entry', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('a'), { type: 'app', startedAt: Date.now() })
  const e = reg.get(appKey('a'))
  t.is(e.anchored, false, 'anchored=false by default')
  t.is(e.anchoredAt, null, 'anchoredAt=null')
  t.is(e.anchoredLength, 0, 'anchoredLength=0')
  t.is(e.lastAnchorCheck, null, 'lastAnchorCheck=null')
})

test('AppRegistry — setAnchored marks entry + records timestamp + length', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('b'), { type: 'app' })
  const before = Date.now()
  const ok = reg.setAnchored(appKey('b'), 42)
  t.is(ok, true, 'returns true')
  const e = reg.get(appKey('b'))
  t.is(e.anchored, true)
  t.is(e.anchoredLength, 42)
  t.ok(e.anchoredAt >= before, 'anchoredAt set')
  t.ok(e.lastAnchorCheck >= before, 'lastAnchorCheck set')
})

test('AppRegistry — setAnchored idempotent + only grows length', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('c'), { type: 'app' })
  reg.setAnchored(appKey('c'), 100)
  const firstAt = reg.get(appKey('c')).anchoredAt
  // Calling again with smaller length doesn't shrink
  reg.setAnchored(appKey('c'), 50)
  const e = reg.get(appKey('c'))
  t.is(e.anchoredLength, 100, 'kept larger value')
  t.is(e.anchoredAt, firstAt, 'first anchoredAt preserved')
})

test('AppRegistry — clearAnchored only fires when previously anchored', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('d'), { type: 'app' })
  // Not anchored yet — clear is a no-op
  t.is(reg.clearAnchored(appKey('d')), false)
  // Anchor it
  reg.setAnchored(appKey('d'), 5)
  // Now clear works
  t.is(reg.clearAnchored(appKey('d'), 'test'), true)
  const e = reg.get(appKey('d'))
  t.is(e.anchored, false)
  t.is(e.anchoredLength, 0)
})

test('AppRegistry — recordAnchorCheck updates lastAnchorCheck without changing state', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('e'), { type: 'app' })
  reg.recordAnchorCheck(appKey('e'))
  const e = reg.get(appKey('e'))
  t.ok(e.lastAnchorCheck > 0, 'recorded timestamp')
  t.is(e.anchored, false, 'state unchanged')
})

test('AppRegistry — anchorStats aggregates correctly', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('1'), { type: 'app' })
  reg.set(appKey('2'), { type: 'app' })
  reg.set(appKey('3'), { type: 'app' })
  reg.setAnchored(appKey('1'), 10)
  reg.recordAnchorCheck(appKey('2')) // checked but not anchored
  // a3 never checked
  const stats = reg.anchorStats()
  t.is(stats.total, 3)
  t.is(stats.anchored, 1)
  t.is(stats.unanchored, 2)
  t.is(stats.neverChecked, 1)
})

test('AppRegistry — catalog() exposes anchored / anchoredAt / anchoredLength', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('f'), { type: 'app' })
  reg.setAnchored(appKey('f'), 7)
  const items = reg.catalog()
  const item = items.find(i => i.appKey === appKey('f'))
  t.is(item.anchored, true)
  t.is(item.anchoredLength, 7)
  t.ok(item.anchoredAt > 0)
})

test('AppRegistry — anchor state survives save/reload', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg1 = new AppRegistry(dir)
  const anchoredAt = Date.now()
  reg1.set(appKey('4'), {
    type: 'app',
    anchored: true,
    anchoredAt,
    anchoredLength: 99,
    lastAnchorCheck: anchoredAt,
    storageProvedDriveVersion: 99,
    storageProvedMetaLength: 99,
    storageProvedBlobLength: 0,
    storageProvedTotalBytes: 512,
    storageProvedMetaFork: 0,
    storageProvedBlobFork: 0,
    maxStorage: 1024
  })
  await reg1.save()

  const reg2 = new AppRegistry(dir)
  await reg2.load()
  const e = reg2.get(appKey('4'))
  t.is(e.anchored, true, 'anchored persisted')
  t.is(e.anchoredLength, 99, 'length persisted')
  t.ok(e.anchoredAt > 0, 'anchoredAt persisted')
})

test('AppRegistry — setAnchored on missing entry returns false', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  t.is(reg.setAnchored('nope', 1), false)
})

// ── Custody-binding diagnostic exposure on catalog() ───────────────────────
//
// Background: v0.8.27's _runCustodyExpiryPass (relay-node/index.js) iterates
// appRegistry.apps and gates the retired-discharge on entry.custodyIntentId.
// Without exposing custodyIntentId on catalog() output (and through
// _redactCatalogEntry), operators have no external way to verify the entry
// actually carries the binding the sweep is gating on — making claim-path
// non-serving-proof failures unpinnable from outside.
//
// custodyIntentId is intentionally NOT redacted: it is already public via
// GET /api/custody/{intentId}/status, so surfacing it on the catalog entry
// only reveals the linkage (intent ↔ appRegistry entry), which is exactly
// what the sweep gates on.

test('AppRegistry — catalog() surfaces custodyIntentId for non-blind entries', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const intentId = 'a'.repeat(64)
  reg.set(appKey('a'), {
    type: 'app',
    blind: false,
    custodyIntentId: intentId,
    startedAt: Date.now()
  })
  const items = reg.catalog()
  const item = items.find(i => i.appKey === appKey('a'))
  t.ok(item, 'entry present in catalog')
  t.is(item.custodyIntentId, intentId, 'custodyIntentId surfaced on non-blind entry')
})

test('AppRegistry — catalog() surfaces custodyIntentId on BLIND/redacted entries (linkage is non-sensitive)', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  const intentId = 'b'.repeat(64)
  const blindId = 'c'.repeat(64)
  reg.set(appKey('b'), {
    type: 'app',
    blind: true,
    blindContentId: blindId,
    custodyIntentId: intentId,
    publisherPubkey: 'd'.repeat(64),
    retainUntil: Date.now() + 5000,
    startedAt: Date.now()
  })
  const items = reg.catalog()
  // Redacted entries have their appKey replaced with blindContentId.
  const item = items.find(i => i.appKey === blindId)
  t.ok(item, 'blind entry present in catalog (keyed by blindContentId after redaction)')
  t.is(item.redacted, true, 'entry is marked redacted')
  t.is(item.publisherPubkey, null, 'publisherPubkey stripped (sensitive provenance)')
  t.is(item.retainUntil, null, 'retainUntil stripped (sensitive commitment signal)')
  t.is(item.custodyIntentId, intentId, 'custodyIntentId PRESERVED — already public via /api/custody/{id}/status, linkage needed for sweep diagnostic')
})

test('AppRegistry — catalog() custodyIntentId defaults to null when not in entry', (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)
  const reg = new AppRegistry(dir)
  reg.set(appKey('e'), { type: 'app', startedAt: Date.now() })
  const item = reg.catalog().find(i => i.appKey === appKey('e'))
  t.is(item.custodyIntentId, null, 'custodyIntentId null for entries without custody binding')
})
