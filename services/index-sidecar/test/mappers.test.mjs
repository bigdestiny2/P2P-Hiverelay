import { test } from 'node:test'
import assert from 'node:assert/strict'
import { appManifestRow, pinRegistryRow, relayDirectoryRow, verificationRow, isIndexable } from '../lib/mappers.js'
import { validateRow } from '../lib/schemas.js'

const KEY = 'a'.repeat(64)
const PUB = 'b'.repeat(64)

const catalogApp = {
  appKey: KEY,
  key: KEY,
  type: 'app',
  name: 'Cool App',
  version: '1.2.3',
  anchored: true,
  anchoredLength: 42,
  sizeBytes: 99,
  author: 'alice',
  publisherPubkey: PUB,
  categories: ['tools'],
  publishedAt: 1700000000000
}

test('isIndexable: public keyed entry yes; private/redacted/unkeyed no', () => {
  assert.equal(isIndexable(catalogApp), true)
  assert.equal(isIndexable({ ...catalogApp, private: true }), false)
  assert.equal(isIndexable({ ...catalogApp, redacted: true }), false)
  assert.equal(isIndexable({ ...catalogApp, visibility: 'private' }), false)
  assert.equal(isIndexable({ name: 'no key' }), false)
  assert.equal(isIndexable(null), false)
})

test('isIndexable: FAILS CLOSED on the relay privacy fields (blind/privacyTier)', () => {
  // The critical fix: a non-blind p2p-only/local-first entry served UN-redacted
  // (custody.redactedCatalog:false) must NOT leak into the public room.
  assert.equal(isIndexable({ ...catalogApp, blind: true }), false)
  assert.equal(isIndexable({ ...catalogApp, privacyTier: 'p2p-only' }), false)
  assert.equal(isIndexable({ ...catalogApp, privacyTier: 'local-first' }), false)
  assert.equal(isIndexable({ ...catalogApp, metadataVisibility: 'redacted' }), false)
  // explicit public still passes
  assert.equal(isIndexable({ ...catalogApp, privacyTier: 'public' }), true)
})

test('appManifestRow: valid row, driveKey set, standalone, redaction null', () => {
  const row = appManifestRow(catalogApp)
  assert.equal(row.appId, KEY)
  assert.equal(row.name, 'Cool App')
  assert.equal(row.driveKey, KEY)
  assert.equal(row.type, 'standalone')
  assert.equal(row.catalogType, 'app')
  assert.equal(row.publisherPubkey, PUB)
  const { valid, errors } = validateRow('app-manifest', row)
  assert.equal(valid, true, JSON.stringify(errors))
  assert.equal(appManifestRow({ ...catalogApp, private: true }), null)
})

test('appManifestRow: hypersite + non-hex key falls back to link', () => {
  const site = { key: KEY, type: 'hypersite', name: 'Site', site: true }
  const row = appManifestRow(site)
  assert.equal(row.type, 'hypersite')
  assert.equal(row.driveKey, KEY)
  const noHex = { appKey: KEY, name: 'X', link: 'hyper://xyz' }
  const r2 = appManifestRow(noHex)
  assert.ok(r2.link, 'has a launch link')
  assert.equal(validateRow('app-manifest', r2).valid, true)
})

test('pinRegistryRow: appKey + anchored→seedState/verified + relayPubkey', () => {
  const row = pinRegistryRow(catalogApp, PUB)
  assert.equal(row.appKey, KEY)
  assert.equal(row.anchored, true)
  assert.equal(row.seedState, 'anchored')
  assert.equal(row.verified, true)
  assert.equal(row.anchoredLength, 42)
  assert.equal(row.relayPubkey, PUB)
  assert.equal(validateRow('pin-registry', row).valid, true)
  // unanchored → accepted, not verified
  const r2 = pinRegistryRow({ appKey: KEY, name: 'x', anchored: false }, PUB)
  assert.equal(r2.seedState, 'accepted')
  assert.equal(r2.verified, false)
})

test('relayDirectoryRow: capabilitySig copied verbatim + health computed', () => {
  const doc = {
    pubkey: PUB,
    gatewayUrl: 'https://relay.example',
    software: 'hiverelay',
    version: '0.18.0',
    region: 'eu',
    features: ['reputation', 'seeding-registry'],
    limitation: { max_storage_bytes: 1000, max_connections: 50 },
    catalog: { total: 10, anchored: 4 },
    attestedAt: 1700000000001,
    signature: { v: 1, sig: 'cc'.repeat(64) }
  }
  const row = relayDirectoryRow(doc, { score: 0.9 })
  assert.equal(row.pubkey, PUB)
  assert.equal(row.gatewayUrl, 'https://relay.example')
  assert.deepEqual(row.capabilitySig, { v: 1, sig: 'cc'.repeat(64) }, 'sig copied for client re-verify')
  assert.equal(row.health.anchorRatio, 0.4)
  assert.equal(row.health.totalCount, 10)
  assert.equal(row.capacity.maxStorageBytes, 1000)
  assert.deepEqual(row.reputation, { score: 0.9 })
  assert.equal(validateRow('relay-directory', row).valid, true)
  // missing gateway → null
  assert.equal(relayDirectoryRow({ pubkey: PUB }), null)
})

test('verificationRow: shapes + rejects incomplete', () => {
  const row = verificationRow({ subjectAppKey: KEY, verifierPubkey: PUB, verdict: 'anchored', method: 'anchor-proof', attestedAt: 5 })
  assert.equal(row.subjectAppKey, KEY)
  assert.equal(row.verdict, 'anchored')
  assert.equal(validateRow('verification', row).valid, true)
  assert.equal(verificationRow({ subjectAppKey: KEY }), null)
  assert.equal(verificationRow({ verdict: 'agree' }), null)
})
