import fs from 'node:fs'
import test from 'brittle'
import b4a from 'b4a'
import {
  CLIENT_COMPOSITION_AUTHORITY_STATUS,
  CLIENT_COMPOSITION_AUTHORITY_V1,
  CLIENT_COMPOSITION_FORMAT_LAYOUT_V1,
  CLIENT_COMPOSITION_SCHEMA_NAMES_V1,
  CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1,
  assertClientCompositionAuthorityReady,
  compileMasterSchemaCatalogForCategory,
  decodeClientCompositionFormatAuthorityV1,
  decodeSchemaCatalog,
  decodeVectorManifest,
  encodeClientCompositionFormatAuthorityV1,
  encodeSchemaCatalog,
  hashAbi,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet,
  hashSpec,
  hashVectorSet,
  isVerifiedClientCompositionAuthorityV1,
  SCHEMA_CATEGORY,
  verifyClientCompositionAuthorityV1,
  verifyClientCompositionFormatAuthorityV1,
  verifyClientCompositionVectorSetV1
} from '../index.js'

const packageUrl = new URL('../', import.meta.url)
const rootUrl = new URL('../../../', import.meta.url)
const artifact = name => fs.readFileSync(new URL(name, packageUrl))
const spec = () => fs.readFileSync(new URL(
  'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V1.md', rootUrl))
const master = () => fs.readFileSync(new URL(
  'docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md', rootUrl), 'utf8')
const metadata = () => JSON.parse(artifact('hiverelay-blind-client-composition-authority-v1.json'))

function vectorMap () {
  return new Map(CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.map(expectation => [
    expectation.path,
    artifact(`vectors/client-composition/${expectation.path}`)
  ]))
}

function authorityInput (overrides = {}) {
  const value = metadata()
  return {
    formatAuthorityBytes: artifact('hiverelay-blind-client-composition-format-v1.cenc'),
    specBytes: spec(),
    schemaCatalogBytes: artifact('hiverelay-blind-client-composition-schema-catalog-v1.cenc'),
    vectorManifestBytes: artifact('hiverelay-blind-client-composition-vector-manifest-v1.cenc'),
    vectors: vectorMap(),
    expectedFormatHash: b4a.from(value.formatHash, 'hex'),
    expectedVectorSetHash: b4a.from(value.vectorSetHash, 'hex'),
    ...overrides
  }
}

test('final client-composition artifacts reproduce and verify as one isolated authority', t => {
  const input = authorityInput()
  const value = metadata()
  const compiled = compileMasterSchemaCatalogForCategory(master(), SCHEMA_CATEGORY.CLIENT_EXAMPLE)
  const compiledCatalog = encodeSchemaCatalog(compiled.entries, { minimum: 6, maximum: 6 })
  const decoded = decodeClientCompositionFormatAuthorityV1(input.formatAuthorityBytes)

  t.is(CLIENT_COMPOSITION_FORMAT_LAYOUT_V1.magic, 'HRBCCF01')
  t.is(decoded.authorityVersion, 1)
  t.is(decoded.formatMajor, 1)
  t.is(decoded.formatMinor, 0)
  t.alike(decoded.specBytes, input.specBytes)
  t.alike(decoded.schemaCatalogBytes, input.schemaCatalogBytes)
  t.alike(compiledCatalog, input.schemaCatalogBytes)
  t.alike(encodeClientCompositionFormatAuthorityV1(input.specBytes, input.schemaCatalogBytes),
    input.formatAuthorityBytes)
  t.is(b4a.toString(hashClientCompositionFormat(input.formatAuthorityBytes), 'hex'), value.formatHash)
  t.is(b4a.toString(hashClientCompositionVectorSet(input.vectorManifestBytes), 'hex'), value.vectorSetHash)

  const verified = verifyClientCompositionAuthorityV1(input)
  t.ok(isVerifiedClientCompositionAuthorityV1(verified))
  t.is(verified.profile, 'client-composition-authority-v1')
  t.is(verified.vectorCount, 18)
  t.alike(verified.schemaNames, CLIENT_COMPOSITION_SCHEMA_NAMES_V1)
  t.ok(CLIENT_COMPOSITION_AUTHORITY_STATUS.releaseReady)
  t.alike(CLIENT_COMPOSITION_AUTHORITY_STATUS.releaseBlockers, [])
  t.alike(assertClientCompositionAuthorityReady(), CLIENT_COMPOSITION_AUTHORITY_STATUS)
  t.is(CLIENT_COMPOSITION_AUTHORITY_V1.formatHash, value.formatHash)
  t.is(CLIENT_COMPOSITION_AUTHORITY_V1.vectorSetHash, value.vectorSetHash)
  t.ok(Object.isFrozen(CLIENT_COMPOSITION_AUTHORITY_V1))
  t.ok(Object.isFrozen(CLIENT_COMPOSITION_AUTHORITY_V1.schemaNames))
  t.ok(Object.isFrozen(CLIENT_COMPOSITION_AUTHORITY_STATUS))
})

test('client-composition API and final metadata are explicitly package-exported', t => {
  const packageManifest = JSON.parse(artifact('package.json'))
  t.is(packageManifest.exports['./client-composition-authority'],
    './client-composition-authority-entry.js')
  t.is(packageManifest.exports['./client-composition-runtime-vectors'],
    './client-composition-runtime-vectors.js')
  t.ok(packageManifest.files.includes('hiverelay-blind-client-composition-authority-v1.json'))
  for (const name of [
    'hiverelay-blind-client-composition-format-v1.cenc',
    'hiverelay-blind-client-composition-schema-catalog-v1.cenc',
    'hiverelay-blind-client-composition-vector-manifest-v1.cenc'
  ]) t.ok(packageManifest.files.includes('*.cenc') && fs.existsSync(new URL(name, packageUrl)), name)
})

test('client-composition vector manifest has a closed path set and executable semantics', t => {
  const input = authorityInput()
  const entries = decodeVectorManifest(input.vectorManifestBytes)
  t.is(entries.length, CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.length)
  t.alike(entries.map(entry => entry.path),
    CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.map(entry => entry.path))
  t.is(entries.filter(entry => entry.path.startsWith('positive/cell-blob-v1-class-')).length, 5)
  const verified = verifyClientCompositionVectorSetV1(input.vectorManifestBytes, input.vectors, {
    schemaCatalogBytes: input.schemaCatalogBytes,
    expectedVectorSetHash: input.expectedVectorSetHash
  })
  t.is(verified.vectorCount, 18)

  const tampered = vectorMap()
  const path = 'positive/read-cell-cap-v1.bin'
  tampered.get(path)[0] ^= 1
  t.exception(() => verifyClientCompositionVectorSetV1(input.vectorManifestBytes, tampered, {
    schemaCatalogBytes: input.schemaCatalogBytes
  }), /does not match its manifest row/)

  const extra = vectorMap()
  extra.set('positive/extra.bin', b4a.from([1]))
  t.exception(() => verifyClientCompositionVectorSetV1(input.vectorManifestBytes, extra, {
    schemaCatalogBytes: input.schemaCatalogBytes
  }), /missing or extra/)
  t.exception(() => verifyClientCompositionVectorSetV1(
    b4a.concat([input.vectorManifestBytes, b4a.from([0])]), input.vectors, {
      schemaCatalogBytes: input.schemaCatalogBytes
    }), /trailing bytes/)

  const accessor = {}
  for (const [key, bytes] of input.vectors) {
    if (key !== path) Object.defineProperty(accessor, key, { value: bytes, enumerable: true })
  }
  Object.defineProperty(accessor, path, { get () { return input.vectors.get(path) }, enumerable: true })
  t.exception(() => verifyClientCompositionVectorSetV1(input.vectorManifestBytes, accessor, {
    schemaCatalogBytes: input.schemaCatalogBytes
  }), /must not use accessors/)
})

test('client-composition authority rejects stale pins, framing drift and foreign catalogs', t => {
  const input = authorityInput()
  const unpinned = { ...input }
  delete unpinned.expectedVectorSetHash
  t.exception(() => verifyClientCompositionAuthorityV1(unpinned), /requires both expected hash pins/)
  const trailing = b4a.concat([input.formatAuthorityBytes, b4a.from([0])])
  t.exception(() => decodeClientCompositionFormatAuthorityV1(trailing), /trailing bytes/)
  const badMagic = b4a.from(input.formatAuthorityBytes)
  badMagic[0] ^= 1
  t.exception(() => decodeClientCompositionFormatAuthorityV1(badMagic), /invalid magic/)
  const hugeLength = b4a.from(input.formatAuthorityBytes)
  hugeLength.fill(0xff, 14, 22)
  t.exception(() => decodeClientCompositionFormatAuthorityV1(hugeLength), /invalid component length/)

  const staleSpec = b4a.concat([input.specBytes.subarray(0, input.specBytes.byteLength - 1), b4a.from('x\n')])
  t.exception(() => verifyClientCompositionFormatAuthorityV1(input.formatAuthorityBytes, {
    specBytes: staleSpec
  }), /expected specification/)
  const wrongHash = b4a.from(input.expectedFormatHash)
  wrongHash[0] ^= 1
  t.exception(() => verifyClientCompositionFormatAuthorityV1(input.formatAuthorityBytes, {
    expectedFormatHash: wrongHash
  }), /expected format hash/)

  const foreignCatalog = artifact('hiverelay-blind-store-schema-catalog-v1.draft.cenc')
  t.exception(() => encodeClientCompositionFormatAuthorityV1(input.specBytes, foreignCatalog),
    /schema catalog/)
})

test('client-composition artifacts cannot perturb WIRE or import relay persistence', t => {
  const wire = JSON.parse(artifact('hiverelay-blind-wire-authority-v1.json'))
  t.is(wire.specHash, '470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9')
  t.is(wire.abiHash, 'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d')
  t.is(wire.vectorSetHash, '7943626bb0e9ffc0886a13e3b6532aa3ebfd60a3c26e4ff0c5842743ae788d07')
  t.is(b4a.toString(hashSpec(fs.readFileSync(new URL(
    'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md', rootUrl))), 'hex'), wire.specHash)
  t.is(b4a.toString(hashAbi(artifact('hiverelay-blind-abi-v1.cenc')), 'hex'), wire.abiHash)
  t.is(b4a.toString(hashVectorSet(artifact('vector-manifest-v1.cenc')), 'hex'), wire.vectorSetHash)

  const input = authorityInput()
  const decodedCatalog = decodeSchemaCatalog(input.schemaCatalogBytes, { minimum: 6, maximum: 6 })
  t.ok(decodedCatalog.every(entry => entry.category === SCHEMA_CATEGORY.CLIENT_EXAMPLE))
  t.alike(decodedCatalog.map(entry => b4a.toString(entry.schemaName, 'ascii')),
    CLIENT_COMPOSITION_SCHEMA_NAMES_V1)
  const forbiddenName = b4a.from('BlindStoreManifestV1', 'ascii')
  const storeCatalog = artifact('hiverelay-blind-store-schema-catalog-v1.draft.cenc')
  for (const [name, bytes] of [
    ['format authority', input.formatAuthorityBytes],
    ['schema catalog', input.schemaCatalogBytes],
    ['vector manifest', input.vectorManifestBytes],
    ['metadata', artifact('hiverelay-blind-client-composition-authority-v1.json')]
  ]) {
    t.absent(bytes.includes(forbiddenName), `${name} excludes relay persistence schema names`)
    t.absent(bytes.includes(storeCatalog), `${name} excludes relay persistence catalog bytes`)
  }
  for (const [vectorPath, bytes] of input.vectors) {
    t.absent(vectorPath.startsWith('store/'), `${vectorPath} is not a persistence path`)
    t.absent(bytes.includes(forbiddenName), `${vectorPath} excludes relay persistence schema names`)
  }
})

test('authority verification copies mutable inputs and rejects shared vector memory', t => {
  const input = authorityInput()
  const verified = verifyClientCompositionAuthorityV1(input)
  const formatHash = b4a.from(verified.formatHash)
  input.formatAuthorityBytes.fill(0)
  input.expectedFormatHash.fill(0)
  t.alike(verified.formatHash, formatHash)

  if (typeof SharedArrayBuffer !== 'undefined') {
    const sharedVectors = vectorMap()
    const path = 'positive/read-cell-cap-v1.bin'
    const source = sharedVectors.get(path)
    const shared = new Uint8Array(new SharedArrayBuffer(source.byteLength))
    shared.set(source)
    sharedVectors.set(path, shared)
    t.exception(() => verifyClientCompositionVectorSetV1(
      authorityInput().vectorManifestBytes, sharedVectors, {
        schemaCatalogBytes: authorityInput().schemaCatalogBytes
      }), /cannot use shared memory/)
  } else {
    t.pass('SharedArrayBuffer is unavailable in this runtime')
  }
})
