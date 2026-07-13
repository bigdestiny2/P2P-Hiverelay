import fs from 'node:fs'
import b4a from 'b4a'
import test from 'brittle'
import {
  STORE_FORMAT_AUTHORITY_LAYOUT_V1,
  STORE_FORMAT_AUTHORITY_V1,
  decodeStoreFormatAuthorityV1,
  encodeStoreFormatAuthorityV1,
  hashStoreFormat,
  verifyStoreFormatAuthorityV1
} from '../index.js'

const artifactUrl = new URL('../hiverelay-blind-store-format-authority-v1.draft.cenc', import.meta.url)
const catalogUrl = new URL('../hiverelay-blind-store-schema-catalog-v1.draft.cenc', import.meta.url)
const hashesUrl = new URL('../vectors/draft/hashes.draft.json', import.meta.url)

test('store-format authority directly binds catalog bytes and frozen layout semantics', t => {
  const artifact = fs.readFileSync(artifactUrl)
  const catalog = fs.readFileSync(catalogUrl)
  const decoded = decodeStoreFormatAuthorityV1(artifact)
  const values = new Map(decoded.entries.map(entry => [entry.name, entry.value]))

  t.is(STORE_FORMAT_AUTHORITY_LAYOUT_V1.magic, 'HRBSFA01')
  t.is(decoded.authorityVersion, 1)
  t.is(decoded.formatMajor, 1)
  t.is(decoded.formatMinor, 1)
  t.alike(decoded.schemaCatalogBytes, catalog)
  t.is(decoded.entries.length, STORE_FORMAT_AUTHORITY_V1.length)
  t.alike(encodeStoreFormatAuthorityV1(catalog), artifact)

  t.is(values.get('layout.writer-lock-final'), 'control/writer.lock.v1')
  t.is(values.get('layout.wal-final'), 'control/wal.v2')
  t.is(values.get('layout.manifest-a-final'), 'control/manifest-a.v1')
  t.is(values.get('layout.manifest-b-final'), 'control/manifest-b.v1')
  t.is(values.get('layout.runtime-binding-final'), 'runtime-binding.v1')
  t.is(values.get('layout.checkpoint-final'), 'control/checkpoint-<hash32>.v1')
  t.is(values.get('layout.snapshot-final'), 'control/snapshot-<hash32>.v1')
  t.is(values.get('layout.genesis-intent-final'), 'control/genesis-intent.v1')
  t.ok(values.get('publication.checkpoint').includes('atomic rename-no-replace'))
  t.ok(values.get('publication.genesis').includes('exactly three sorted kind6/subtype1 family-global'))
  t.ok(values.get('publication.manifest').includes('atomic rename-replace'))
  t.ok(values.get('recovery.genesis').includes('WAL/data without the intent'))
  t.ok(values.get('recovery.manifest-selection').includes('high=low+1'))
  t.ok(values.get('retention.wal').includes('sequence 1'))
  t.ok(values.get('binding.runtime-root').includes('exactly 213 bytes'))
  t.ok(values.get('binding.runtime-verification').includes('unforgeable local verifier authority'))
  t.ok(values.get('control-snapshot.cell-value-codecs').includes(
    '1/5=BlindCellAtomicCommittedPutSpendSnapshotV1'))
  t.ok(values.get('wal.cell.put-atomic-committed').includes(
    'recordType=17 payload is canonical BlindPutAtomicCommittedStoreV1'))
  for (const name of [
    'unsupported.checkpoint-gc',
    'unsupported.migration',
    'unsupported.wal-pruning'
  ]) t.ok(values.get(name).startsWith('UNSUPPORTED;'))
  t.absent(values.get('unsupported.genesis'))

  const hashes = JSON.parse(fs.readFileSync(hashesUrl, 'utf8'))
  t.is(b4a.toString(hashStoreFormat(artifact), 'hex'), hashes.storeFormatHash)

  const verified = verifyStoreFormatAuthorityV1(artifact, {
    schemaCatalogBytes: catalog,
    expectedStoreFormatHash: b4a.from(hashes.storeFormatHash, 'hex')
  })
  t.is(verified.formatMajor, 1)
  t.is(verified.formatMinor, 1)
  t.alike(verified.authorityBytes, artifact)
  t.alike(verified.schemaCatalogBytes, catalog)
  t.is(b4a.toString(verified.storeFormatHash, 'hex'), hashes.storeFormatHash)
})

test('store-format authority rejects non-canonical framing and ordering', t => {
  const artifact = fs.readFileSync(artifactUrl)
  const catalog = fs.readFileSync(catalogUrl)
  t.exception(() => decodeStoreFormatAuthorityV1(b4a.concat([artifact, b4a.from([0])])), /trailing bytes/)
  const badMagic = b4a.from(artifact)
  badMagic[0] ^= 1
  t.exception(() => decodeStoreFormatAuthorityV1(badMagic), /invalid magic/)
  const oldFormatMinor = b4a.from(artifact)
  oldFormatMinor[13] = 0
  t.exception(() => decodeStoreFormatAuthorityV1(oldFormatMinor), /unsupported version/)
  t.exception(() => encodeStoreFormatAuthorityV1(catalog, [
    STORE_FORMAT_AUTHORITY_V1[1],
    STORE_FORMAT_AUTHORITY_V1[0]
  ]), /strictly raw-ASCII sorted/)
})

test('store-format hash changes for either catalog-byte or authority-rule drift', t => {
  const catalog = fs.readFileSync(catalogUrl)
  const canonical = encodeStoreFormatAuthorityV1(catalog)
  const changedCatalog = b4a.from(catalog)
  changedCatalog[changedCatalog.byteLength - 1] ^= 1
  const changedEntries = STORE_FORMAT_AUTHORITY_V1.map(entry => ({ ...entry }))
  changedEntries[changedEntries.length - 1].value += ' '

  const canonicalHash = b4a.toString(hashStoreFormat(canonical), 'hex')
  t.not(b4a.toString(hashStoreFormat(encodeStoreFormatAuthorityV1(changedCatalog)), 'hex'), canonicalHash)
  t.not(b4a.toString(hashStoreFormat(encodeStoreFormatAuthorityV1(catalog, changedEntries)), 'hex'), canonicalHash)
})

test('complete store-format verification rejects stale catalogs, artifacts, and signed hash pins', t => {
  const artifact = fs.readFileSync(artifactUrl)
  const catalog = fs.readFileSync(catalogUrl)
  const expectedHash = hashStoreFormat(artifact)

  const staleCatalog = b4a.from(catalog)
  staleCatalog[staleCatalog.byteLength - 1] ^= 1
  t.exception(() => verifyStoreFormatAuthorityV1(artifact, {
    schemaCatalogBytes: staleCatalog,
    expectedStoreFormatHash: expectedHash
  }), /expected complete schema catalog/)

  const staleArtifact = encodeStoreFormatAuthorityV1(staleCatalog)
  t.exception(() => verifyStoreFormatAuthorityV1(staleArtifact, {
    schemaCatalogBytes: staleCatalog,
    expectedStoreFormatHash: expectedHash
  }), /expected storeFormatHash/)

  const wrongSignedPin = b4a.from(expectedHash)
  wrongSignedPin[0] ^= 1
  t.exception(() => verifyStoreFormatAuthorityV1(artifact, {
    schemaCatalogBytes: catalog,
    expectedStoreFormatHash: wrongSignedPin
  }), /expected storeFormatHash/)

  const changedRules = STORE_FORMAT_AUTHORITY_V1.map(entry => ({ ...entry }))
  changedRules[0].value += ' '
  const ruleDrift = encodeStoreFormatAuthorityV1(catalog, changedRules)
  t.exception(() => verifyStoreFormatAuthorityV1(ruleDrift, {
    schemaCatalogBytes: catalog,
    expectedStoreFormatHash: hashStoreFormat(ruleDrift)
  }), /frozen source authority/)
})
