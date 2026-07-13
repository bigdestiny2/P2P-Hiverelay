import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  encodeStoreFormatAuthorityV1,
  hashStoreFormat
} from '@hiverelay/blind-protocol'
import {
  BlindStoreFormatAuthorityError,
  createBlindStoreFormatAuthorityBinding,
  inspectBlindStoreFormatAuthorityBinding,
  loadBundledBlindStoreFormatAuthority
} from '../store-format-binding.js'
import {
  BLIND_CELL_STORE_FORMAT_BINDING_BLOCKER,
  BlindCellStorageEngine
} from '../storage-engine.js'

const authorityUrl = new URL(
  '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
  import.meta.url
)
const catalogUrl = new URL(
  '../../blind-protocol/hiverelay-blind-store-schema-catalog-v1.draft.cenc',
  import.meta.url
)

async function candidate () {
  const [authorityBytes, schemaCatalogBytes] = await Promise.all([
    fs.readFile(authorityUrl),
    fs.readFile(catalogUrl)
  ])
  return {
    authorityBytes,
    schemaCatalogBytes,
    expectedStoreFormatHash: hashStoreFormat(authorityBytes),
    expectedFormatMajor: 1,
    expectedFormatMinor: 1
  }
}

test('daemon store-format binding brands the exact generated authority and returns copies', async t => {
  const input = await candidate()
  const binding = createBlindStoreFormatAuthorityBinding(input)
  const first = inspectBlindStoreFormatAuthorityBinding(binding)
  const expected = b4a.from(first.storeFormatHash)

  t.is(first.authorityVersion, 1)
  t.is(first.formatMajor, 1)
  t.is(first.formatMinor, 1)
  t.is(first.publicationFinal, false)
  first.storeFormatHash[0] ^= 1
  t.alike(inspectBlindStoreFormatAuthorityBinding(binding).storeFormatHash, expected)

  const bundled = await loadBundledBlindStoreFormatAuthority(input)
  t.alike(inspectBlindStoreFormatAuthorityBinding(bundled).storeFormatHash, expected)
  t.exception(() => inspectBlindStoreFormatAuthorityBinding({
    authorityVersion: 1,
    formatMajor: 1,
    formatMinor: 0,
    storeFormatHash: expected,
    publicationFinal: false
  }), BlindStoreFormatAuthorityError)
})

test('daemon store-format binding rejects stale artifacts, catalogs, pins, and format tuples', async t => {
  const input = await candidate()

  const staleCatalog = b4a.from(input.schemaCatalogBytes)
  staleCatalog[staleCatalog.byteLength - 1] ^= 1
  t.exception(() => createBlindStoreFormatAuthorityBinding({
    ...input,
    schemaCatalogBytes: staleCatalog
  }), /expected complete schema catalog/)

  const staleArtifact = encodeStoreFormatAuthorityV1(staleCatalog)
  t.exception(() => createBlindStoreFormatAuthorityBinding({
    ...input,
    authorityBytes: staleArtifact,
    schemaCatalogBytes: staleCatalog
  }), /expected storeFormatHash/)

  const wrongSignedPin = b4a.from(input.expectedStoreFormatHash)
  wrongSignedPin[0] ^= 1
  t.exception(() => createBlindStoreFormatAuthorityBinding({
    ...input,
    expectedStoreFormatHash: wrongSignedPin
  }), /expected storeFormatHash/)

  t.exception(() => createBlindStoreFormatAuthorityBinding({
    ...input,
    expectedFormatMinor: 0
  }), /does not match expected 1\.0/)
})

test('cell engine consumes only a branded exact store-format binding without claiming publication', async t => {
  const input = await candidate()
  const binding = createBlindStoreFormatAuthorityBinding(input)
  const root = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'blind-format-binding-'))
  await fs.chmod(root, 0o700)
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))

  const engineOptions = {
    root,
    relayPublicKey: b4a.alloc(32, 0x11),
    partitionKey: b4a.alloc(32, 0x22),
    ownerFenceTokenHash: b4a.alloc(32, 0x33),
    durabilityContinuityHash: b4a.alloc(32, 0x44),
    durabilityProfileId: 1,
    initialEpochFloor: 1,
    nowUnixMillis: () => 21600000n,
    autoClock: false
  }
  t.exception(() => new BlindCellStorageEngine({
    ...engineOptions,
    storeFormatAuthority: {
      authorityVersion: 1,
      formatMajor: 1,
      formatMinor: 0,
      storeFormatHash: input.expectedStoreFormatHash,
      publicationFinal: false
    }
  }), /forged or unsupported/)

  const engine = new BlindCellStorageEngine({ ...engineOptions, storeFormatAuthority: binding })
  await engine.open()
  t.teardown(() => engine.close())
  const status = engine.status()
  t.is(status.storeFormat.bound, true)
  t.alike(status.storeFormat.storeFormatHash, input.expectedStoreFormatHash)
  t.is(status.storeFormat.publicationFinal, false)
  t.absent(status.blockers.includes(BLIND_CELL_STORE_FORMAT_BINDING_BLOCKER))
  t.ok(status.blockers.includes('FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED'))
  await engine.close()
})
