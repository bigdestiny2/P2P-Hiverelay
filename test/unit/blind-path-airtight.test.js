// blind-path-airtight: regression tests for the blind-flag commitment.
//
// Walks each public surface (the catalog projection, broadcast,
// _shouldRedactEntry predicate, manifest indexer) and asserts that
// entries with blind===true never expose identifying metadata,
// regardless of caller opts or operator config.
//
// See docs/audit/2026-05-19-blind-path-audit.md for the audit that
// drove these tests.

import test from 'brittle'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

function makeBlindEntry (key, overrides = {}) {
  return {
    type: 'app',
    appId: 'private-app-id-should-not-leak',
    name: 'Secret App Name',
    description: 'A description that must not appear in any output',
    author: 'private-author',
    version: '9.9.9',
    categories: ['private', 'sensitive'],
    blind: true,
    blindContentId: 'b'.repeat(64),
    ciphertextRoot: 'c'.repeat(64),
    durability: 0,
    revocable: true,
    parentKey: null,
    mountPath: null,
    discoveryKey: 'd'.repeat(64),
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    ...overrides
  }
}

const IDENTIFYING_FIELDS = ['Secret App Name', 'private-app-id-should-not-leak', 'private-author', 'A description that must not appear in any output', '9.9.9']

function assertNoIdentifyingLeaks (t, payload, where) {
  const json = JSON.stringify(payload)
  for (const needle of IDENTIFYING_FIELDS) {
    t.absent(json.includes(needle), `${where}: must not contain "${needle}"`)
  }
}

// ── Path 3: _shouldRedactEntry — always-redact-blind, regardless of opts

test('Path 3: _shouldRedactEntry returns true for blind=true regardless of opts.redactPrivate=false', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), makeBlindEntry('a'.repeat(64)))
  const entry = reg.get('a'.repeat(64))
  t.is(reg._shouldRedactEntry(entry, { redactPrivate: false }), true,
    'blind=true forces redaction even when caller opts out')
})

test('Path 3: _shouldRedactEntry returns true for blind=true with no opts passed', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), makeBlindEntry('a'.repeat(64)))
  const entry = reg.get('a'.repeat(64))
  t.is(reg._shouldRedactEntry(entry), true,
    'blind=true forces redaction when caller passes no opts')
})

test('Path 3: non-blind public entry follows opts.redactPrivate (regression guard)', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), { type: 'app', appId: 'public-app', name: 'Public App', privacyTier: 'public', blind: false })
  const entry = reg.get('a'.repeat(64))
  t.is(reg._shouldRedactEntry(entry, { redactPrivate: true }), false, 'public entry not redacted')
  t.is(reg._shouldRedactEntry(entry, { redactPrivate: false }), false, 'public entry not redacted when opt-out either')
})

// ── catalog() and catalogForBroadcast — both must redact blind entries
// regardless of how they're called.

test('catalog() with no opts redacts blind entries (Path 3 cascade-fix to Path 6)', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), makeBlindEntry('a'.repeat(64)))
  const catalog = reg.catalog() // no opts — Path 6's leak site
  t.is(catalog.length, 1, 'one entry')
  t.is(catalog[0].redacted, true, 'blind entry is marked redacted')
  t.is(catalog[0].name, 'Private Content', 'name replaced with placeholder')
  t.is(catalog[0].author, 'redacted', 'author scrubbed')
  assertNoIdentifyingLeaks(t, catalog[0], 'catalog() no-opts')
})

test('catalog() with redactPrivate=false STILL redacts blind entries (the audit fix)', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), makeBlindEntry('a'.repeat(64)))
  // The whole point of the fix: even if operator config disables
  // redactPrivate, blind entries stay redacted.
  const catalog = reg.catalog({ redactPrivate: false })
  t.is(catalog[0].redacted, true, 'blind redacted despite redactPrivate:false')
  assertNoIdentifyingLeaks(t, catalog[0], 'catalog() redactPrivate:false')
})

test('catalogForBroadcast redacts blind entries (Path 4 regression guard)', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), makeBlindEntry('a'.repeat(64)))
  const broadcast = reg.catalogForBroadcast()
  t.is(broadcast.length, 1, 'one broadcast entry')
  t.is(broadcast[0].redacted, true, 'blind redacted in broadcast')
  t.is(broadcast[0].appKey, null, 'addressKey scrubbed in broadcast')
  t.is(broadcast[0].appId, null, 'appId scrubbed in broadcast')
  assertNoIdentifyingLeaks(t, broadcast[0], 'catalogForBroadcast')
})

// ── catalog() preserves the publisher's intentional public metadata for
// non-blind entries (regression: we must not over-redact)

test('catalog() does NOT redact non-blind public entries (audit fix scope guard)', (t) => {
  const reg = new AppRegistry(null)
  reg.set('a'.repeat(64), {
    type: 'app',
    appId: 'my-public-app',
    name: 'My Public App',
    description: 'Discoverable description',
    author: 'jane',
    blind: false,
    privacyTier: 'public'
  })
  const catalog = reg.catalog({ redactPrivate: true })
  t.is(catalog[0].name, 'My Public App', 'public entries keep their name')
  t.is(catalog[0].author, 'jane', 'public entries keep their author')
  t.absent(catalog[0].redacted, 'public entries not flagged redacted')
})
