// app-registry-provenance: v0.8.18 Phase A regression tests for the
// catalog provenance surfacing.
//
// Threat model context: federation receiving relays need to know
// whether an incoming catalog entry carries publisher commitment
// (publisherPubkey + durability + non-revocable) or is pure-anonymous
// gossip. Before v0.8.18, catalogForBroadcast() stripped all four
// fields, leaving downstream relays unable to distinguish published
// content from mirrored junk — which is what produced the 444/455
// (97.6%) pure-anonymous-no-commitment fed-junk on utah-us.
//
// This Phase A fix surfaces those fields for NON-redacted entries
// only. Blind/redacted entries MUST still strip them — otherwise
// the cascade would leak publisher identity for blind drives.
//
// Tests:
//   1. Non-blind entry: all 4 fields surface in catalog() + broadcast.
//   2. Blind entry: all 4 fields are forcibly null/0/true in catalog()
//      and broadcast even when set on the underlying entry.
//   3. Persistence round-trip: save() + load() preserve all 3 of the
//      newly-persisted fields (publisherPubkey, durability, revocable)
//      across a simulated restart, AND surface them post-load.

import test from 'brittle'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

test('catalog() surfaces publisherPubkey/durability/revocable/retainUntil for non-blind entries', (t) => {
  const registry = new AppRegistry(null)
  const pub = 'a'.repeat(64)
  const appKey = 'b'.repeat(64)
  const future = Date.now() + 7 * 24 * 60 * 60 * 1000 // 7d out

  registry.set(appKey, {
    type: 'app',
    appId: 'commit-app',
    version: '1.0.0',
    name: 'Committed App',
    publisherPubkey: pub,
    durability: 2,
    revocable: false,
    retainUntil: future
  })

  const entry = registry.catalog()[0]
  t.is(entry.publisherPubkey, pub, 'publisherPubkey surfaced')
  t.is(entry.durability, 2, 'durability surfaced')
  t.is(entry.revocable, false, 'revocable=false surfaced')
  t.is(entry.retainUntil, future, 'retainUntil surfaced')
  t.is(entry.redacted, undefined, 'non-blind entry not marked redacted')
})

test('catalogForBroadcast() surfaces the same 4 provenance fields for non-blind entries', (t) => {
  const registry = new AppRegistry(null)
  const pub = 'c'.repeat(64)
  const appKey = 'd'.repeat(64)
  const future = Date.now() + 24 * 60 * 60 * 1000

  registry.set(appKey, {
    type: 'app',
    appId: 'broadcast-app',
    version: '1.0.0',
    publisherPubkey: pub,
    durability: 1,
    revocable: true,
    retainUntil: future
  })

  const broadcast = registry.catalogForBroadcast()[0]
  t.is(broadcast.publisherPubkey, pub, 'broadcast carries publisherPubkey')
  t.is(broadcast.durability, 1, 'broadcast carries durability')
  t.is(broadcast.revocable, true, 'broadcast carries revocable')
  t.is(broadcast.retainUntil, future, 'broadcast carries retainUntil')
  t.is(broadcast.redacted, false, 'non-blind not redacted')
})

test('catalog() strips all 4 provenance fields for BLIND entries (cascade with v0.8.15 audit)', (t) => {
  const registry = new AppRegistry(null)
  const pub = 'e'.repeat(64)
  const future = Date.now() + 24 * 60 * 60 * 1000

  registry.set('f'.repeat(64), {
    type: 'drive',
    appId: 'blind-app',
    name: 'Alice Tax Docs',
    blind: true,
    publisherPubkey: pub,
    durability: 3,
    revocable: false,
    retainUntil: future
  })

  // catalog() with no opts — blind entries are unconditionally redacted
  // (v0.8.15 Path 3 contract).
  const entry = registry.catalog()[0]
  t.is(entry.redacted, true, 'blind entry is redacted')
  t.is(entry.publisherPubkey, null, 'publisherPubkey scrubbed for blind')
  t.is(entry.durability, 0, 'durability reset to 0 for blind')
  t.is(entry.revocable, true, 'revocable defaulted to true for blind')
  t.is(entry.retainUntil, null, 'retainUntil scrubbed for blind')

  // Same contract under redactPrivate:false — operator config cannot
  // override the publisher's blind commitment.
  const optOut = registry.catalog({ redactPrivate: false })[0]
  t.is(optOut.publisherPubkey, null, 'redactPrivate:false STILL strips publisherPubkey')
  t.is(optOut.durability, 0, 'redactPrivate:false STILL resets durability')
  t.is(optOut.revocable, true, 'redactPrivate:false STILL resets revocable')
  t.is(optOut.retainUntil, null, 'redactPrivate:false STILL strips retainUntil')
})

test('catalogForBroadcast() strips all 4 provenance fields for BLIND entries', (t) => {
  const registry = new AppRegistry(null)
  const pub = 'a'.repeat(64)
  const future = Date.now() + 24 * 60 * 60 * 1000

  registry.set('1'.repeat(64), {
    type: 'drive',
    appId: 'blind-broadcast',
    blind: true,
    publisherPubkey: pub,
    durability: 2,
    revocable: false,
    retainUntil: future
  })

  const broadcast = registry.catalogForBroadcast()[0]
  t.is(broadcast.redacted, true, 'blind entry redacted in broadcast')
  t.is(broadcast.publisherPubkey, null, 'broadcast strips publisherPubkey for blind')
  t.is(broadcast.durability, 0, 'broadcast resets durability for blind')
  t.is(broadcast.revocable, true, 'broadcast resets revocable for blind')
  t.is(broadcast.retainUntil, null, 'broadcast strips retainUntil for blind')
})

test('catalogForBroadcast() handles missing provenance gracefully (anonymous mirror)', (t) => {
  // The 97.6% case: most existing entries on the fleet have no
  // publisherPubkey at all. Broadcast must emit null/0/true defaults
  // rather than crashing or carrying ghost values.
  const registry = new AppRegistry(null)
  registry.set('2'.repeat(64), {
    type: 'app',
    appId: 'anon-mirror',
    version: '1.0.0'
    // no publisherPubkey, durability, revocable, retainUntil
  })

  const broadcast = registry.catalogForBroadcast()[0]
  t.is(broadcast.publisherPubkey, null, 'missing publisherPubkey emits null')
  t.is(broadcast.durability, 0, 'missing durability emits 0')
  t.is(broadcast.revocable, true, 'missing revocable defaults to true')
  t.is(broadcast.retainUntil, null, 'missing retainUntil emits null')
})

test('save() + load() round-trip preserves publisherPubkey/durability/revocable', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-provenance-'))
  try {
    const pub = 'b'.repeat(64)
    const appKey = '3'.repeat(64)

    // Write phase: set up registry, force a save.
    const writer = new AppRegistry(dir)
    writer.set(appKey, {
      type: 'app',
      appId: 'restart-app',
      version: '2.0.0',
      publisherPubkey: pub,
      durability: 2,
      revocable: false
    })
    await writer.save()

    // Read phase: fresh registry on the same dir simulates a restart.
    const reader = new AppRegistry(dir)
    const reseedEntries = await reader.load()

    // In-memory entry has the fields restored:
    const restored = reader.get(appKey)
    t.is(restored.publisherPubkey, pub, 'publisherPubkey survives restart')
    t.is(restored.durability, 2, 'durability survives restart')
    t.is(restored.revocable, false, 'revocable=false survives restart')

    // Reseed entries (what gets passed back to seedApp on startup) also
    // carry the provenance — otherwise the in-memory entry would be
    // clobbered by _seedAppInner using undefined opts.
    const reseed = reseedEntries.find(e => e.appKey === appKey)
    t.ok(reseed, 'reseed entry found')
    t.is(reseed.publisherPubkey, pub, 'reseed.publisherPubkey forwarded')
    t.is(reseed.durability, 2, 'reseed.durability forwarded')
    t.is(reseed.revocable, false, 'reseed.revocable forwarded')

    // And the catalog/broadcast surface them post-load.
    const catalog = reader.catalog()[0]
    t.is(catalog.publisherPubkey, pub, 'catalog surfaces post-load')
    const broadcast = reader.catalogForBroadcast()[0]
    t.is(broadcast.publisherPubkey, pub, 'broadcast surfaces post-load')
    t.is(broadcast.durability, 2, 'broadcast.durability post-load')
    t.is(broadcast.revocable, false, 'broadcast.revocable post-load')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('older registry files (pre-v0.8.18) load with sane defaults', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-provenance-old-'))
  try {
    // Simulate a pre-v0.8.18 registry file by writing one without
    // publisherPubkey/durability/revocable fields.
    const { writeFile } = await import('fs/promises')
    const filePath = join(dir, 'app-registry.json')
    const oldEntry = {
      appKey: '4'.repeat(64),
      appId: 'legacy-app',
      type: 'app',
      version: '1.0.0',
      privacyTier: 'public',
      blind: false
      // no publisherPubkey, durability, revocable
    }
    await writeFile(filePath, JSON.stringify([oldEntry]), 'utf8')

    const reader = new AppRegistry(dir)
    await reader.load()
    const restored = reader.get('4'.repeat(64))
    t.is(restored.publisherPubkey, null, 'old registry → null publisherPubkey')
    t.is(restored.durability, 0, 'old registry → durability 0')
    t.is(restored.revocable, true, 'old registry → revocable true (default)')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
