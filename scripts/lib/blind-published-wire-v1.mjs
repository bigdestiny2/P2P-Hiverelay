import fs from 'node:fs'
import path from 'node:path'
import b4a from 'b4a'
import {
  MASTER_SCHEMA_INVENTORY,
  SCHEMA_DEFINITION_KIND,
  auditMasterSchemaInventory
} from '../../packages/blind-protocol/master-schema-inventory.js'
import {
  ABI_STATUS,
  SCHEMA_CATEGORY,
  SCHEMA_NAMES_BY_CATEGORY
} from '../../packages/blind-protocol/registry.js'
import {
  canonicalSchemaDefinitionV1,
  decodeSchemaCatalog,
  encodeSchemaCatalog
} from '../../packages/blind-protocol/schema-meta.js'
import {
  decodeCanonical,
  encodeCanonical
} from '../../packages/blind-protocol/codec.js'
import { schemaCatalogEntryV1 } from '../../packages/blind-protocol/schemas.js'
import {
  blake2b256,
  decodeVectorManifest,
  hashAbi,
  hashSpec,
  hashVectorSet
} from '../../packages/blind-protocol/hashes.js'
import {
  WIRE_RUNTIME_AUTHORITY,
  WIRE_RUNTIME_AUTHORITY_STATUS,
  assertWireAuthorityReady
} from '../../packages/blind-protocol/wire-runtime-authority.js'
import {
  SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY
} from '../../packages/blind-protocol/schema-catalog-runtime-authority.js'

const PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES = Object.freeze([
  'BlindForwardRouteHopV1',
  'BlindForwardRouteScopeV1'
])

const PUBLISHED_WIRE_V1_DEFERRED_DEPENDENCY_EDGES = Object.freeze([
  'BlindForwardHopOpenV1->BlindForwardRouteScopeV1'
])

const PUBLISHED_WIRE_V1_AUTHORITY = Object.freeze({
  profile: 'wire-authority-v1',
  protocolFamily: 'hiverelay-blind',
  protocolMajor: 1,
  protocolMinor: 0,
  specArtifact: 'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md',
  abiArtifact: 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  vectorManifestArtifact: 'packages/blind-protocol/vector-manifest-v1.cenc',
  specHash: '470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9',
  abiHash: 'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d',
  vectorSetHash: '09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78',
  wireSchemaCount: 71,
  operationCount: 22,
  errorCount: 20,
  domainCount: 39,
  vectorCount: 233
})

const EXPECTED_CATEGORY_COUNTS = Object.freeze({
  [SCHEMA_CATEGORY.WIRE]: 73,
  [SCHEMA_CATEGORY.EVIDENCE]: 28,
  [SCHEMA_CATEGORY.CLIENT_EXAMPLE]: 6,
  [SCHEMA_CATEGORY.INTERNAL_STORE]: 38,
  [SCHEMA_CATEGORY.PRIVATE_IPC]: 7
})

const EXPECTED_VECTOR_PREFIX_COUNTS = Object.freeze({
  'registry/schemas/': 71,
  'registry/operations/': 22,
  'registry/domains/': 39,
  'registry/errors/': 20,
  'registry/admission-costs/': 11
})

const RESERVED_NON_WIRE_VECTOR_ROOTS = new Set([
  'client-composition',
  'draft',
  'evidence',
  'store'
])

function drift (message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause })
  error.code = 'BLIND_PUBLISHED_WIRE_V1_DRIFT'
  throw error
}

function invariant (condition, message) {
  if (!condition) drift(message)
}

function compareJson (left, right) {
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object') {
    return left === right
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((value, index) => compareJson(value, right[index]))
  }
  const leftKeys = Object.keys(left).sort()
  const rightKeys = Object.keys(right).sort()
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && compareJson(left[key], right[key]))
}

function exactArray (actual, expected, message) {
  invariant(Array.isArray(actual) && actual.length === expected.length &&
    actual.every((value, index) => value === expected[index]), message)
}

function hex (bytes) {
  return b4a.toString(bytes, 'hex')
}

function asBytes (value, label) {
  if (!value || typeof value.byteLength !== 'number') drift(`${label} did not return bytes`)
  return b4a.from(value)
}

function canonicalTextBytes (read, absolute, label) {
  const bytes = read(absolute, label)
  if (bytes.byteLength === 0 || bytes[bytes.byteLength - 1] !== 0x0a || bytes.includes(0x0d) ||
      (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) {
    drift(`${label} is not canonical UTF-8/LF/no-BOM/exact-final-LF text`)
  }
  return bytes
}

function canonicalJson (read, absolute, expected, label) {
  const bytes = canonicalTextBytes(read, absolute, label)
  let value
  try {
    value = JSON.parse(b4a.toString(bytes, 'utf8'))
  } catch (error) {
    drift(`${label} is not valid JSON`, error)
  }
  const canonical = b4a.from(JSON.stringify(value, null, 2) + '\n')
  invariant(b4a.equals(bytes, canonical), `${label} is not canonical pretty JSON`)
  invariant(compareJson(value, expected), `${label} does not equal the fixed published WIRE v1 authority`)
  return value
}

function declarationHeader (schemaName, definitionKind) {
  const escaped = schemaName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return definitionKind === SCHEMA_DEFINITION_KIND.INLINE_UNION
    ? new RegExp(`^${escaped}\\s*=\\s*tagged union\\s*\\{`, 'm')
    : new RegExp(`^${escaped}\\s*\\{`, 'm')
}

function extractDeclaration (masterText, inventory) {
  const header = declarationHeader(inventory.schemaName, inventory.definitionKind)
  const match = header.exec(masterText)
  if (!match) drift(`published schema ${inventory.schemaName} is missing from the stable master`)
  const second = header.exec(masterText.slice(match.index + match[0].length))
  if (second) drift(`published schema ${inventory.schemaName} is duplicated in the stable master`)
  let depth = 0
  let closing = -1
  for (let index = match.index; index < masterText.length; index++) {
    if (masterText[index] === '{') depth++
    if (masterText[index] === '}') {
      depth--
      if (depth === 0) {
        closing = index + 1
        break
      }
    }
  }
  if (closing < 0) drift(`published schema ${inventory.schemaName} is unterminated in the stable master`)
  const declaration = masterText.slice(match.index, closing)
  if (declaration.includes('\r') || declaration.endsWith('\n')) {
    drift(`published schema ${inventory.schemaName} has a non-canonical declaration`)
  }
  return b4a.from(declaration, 'utf8')
}

function dependencyNames (sourceDeclaration, schemaName, knownSchemaNames) {
  return [...new Set((b4a.toString(sourceDeclaration, 'utf8')
    .match(/\b[A-Za-z][A-Za-z0-9]*V1\b/g) || [])
    .filter(name => name !== schemaName && knownSchemaNames.has(name)))].sort()
}

function listedFiles (directory, prefix = '') {
  const result = []
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isDirectory()) result.push(...listedFiles(path.join(directory, entry.name), relative))
    else if (entry.isFile()) result.push(relative)
    else drift(`WIRE vector closure contains a non-file entry: ${relative}`)
  }
  return result
}

function defaultWireVectorPaths (directory) {
  return listedFiles(directory)
    .filter(relative => !RESERVED_NON_WIRE_VECTOR_ROOTS.has(relative.split('/')[0]))
    .sort()
}

function safeActualPaths (values) {
  invariant(Array.isArray(values), 'WIRE vector path lister did not return an array')
  const result = values.map(value => {
    invariant(typeof value === 'string' && value.length > 0 && !value.includes('\\') &&
      !value.startsWith('/') && !value.includes('\0') &&
      value !== '..' && !value.startsWith('../') && !value.includes('/../'),
    'WIRE vector path lister returned an unsafe path')
    return value
  }).sort()
  invariant(new Set(result).size === result.length, 'WIRE vector path closure contains duplicates')
  return result
}

function normalizedOptions (options) {
  if (options == null) options = {}
  invariant(typeof options === 'object' && !Array.isArray(options), 'verifier options must be an object')
  const optionNames = Object.keys(options)
  invariant(optionNames.every(name => name === 'root' || name === 'io'),
    'verifier options contain an unknown key')
  const root = path.resolve(options.root || path.resolve(import.meta.dirname, '../..'))
  const io = options.io == null ? {} : options.io
  invariant(typeof io === 'object' && !Array.isArray(io), 'verifier io must be an object')
  const ioNames = Object.keys(io)
  invariant(ioNames.every(name => name === 'readFile' || name === 'listWireVectorPaths'),
    'verifier io contains an unknown key')
  invariant(io.readFile == null || typeof io.readFile === 'function', 'verifier readFile must be a function')
  invariant(io.listWireVectorPaths == null || typeof io.listWireVectorPaths === 'function',
    'verifier listWireVectorPaths must be a function')
  const readFile = io.readFile || (absolute => fs.readFileSync(absolute))
  const listWireVectorPaths = io.listWireVectorPaths || defaultWireVectorPaths
  return {
    root,
    read (absolute, label) {
      try {
        return asBytes(readFile(absolute), label)
      } catch (error) {
        if (error && error.code === 'BLIND_PUBLISHED_WIRE_V1_DRIFT') throw error
        drift(`could not read ${label}`, error)
      }
    },
    listWireVectorPaths
  }
}

function verifyCurrentCandidateState (masterText) {
  const audit = auditMasterSchemaInventory(masterText)
  invariant(audit.ok === false, 'current master unexpectedly became inventory-complete')
  exactArray(audit.missingMasterDefinitions, PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES,
    'current master is not missing exactly the two documented FORWARD candidates')
  invariant(audit.namedMasterSchemaCount === 149, 'current master named-schema count changed')
  invariant(audit.catalogSchemaCount === 152, 'current inventory schema count changed')
  for (const [name, values] of [
    ['duplicate master names', audit.duplicateMasterNames],
    ['unclassified master names', audit.unclassifiedMasterNames],
    ['inline-union definition errors', audit.inlineUnionDefinitionErrors],
    ['ownership errors', audit.ownershipErrors],
    ['dependency errors', audit.dependencyErrors]
  ]) exactArray(values, [], `current master has ${name}`)
  invariant(compareJson(audit.categoryTotals, EXPECTED_CATEGORY_COUNTS),
    'current schema category totals changed')

  invariant(ABI_STATUS.profile === PUBLISHED_WIRE_V1_AUTHORITY.profile,
    'current registry profile changed')
  invariant(ABI_STATUS.releaseReady === false,
    'current candidate registry unexpectedly became release-ready')
  exactArray(ABI_STATUS.releaseBlockers, ['FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING'],
    'current registry release blockers changed')
  exactArray(ABI_STATUS.wireMissingSchemaNames, [], 'current registry has missing executable WIRE schemas')
  invariant(ABI_STATUS.wireRequiredSchemaNames.length === 73,
    'current candidate WIRE inventory count changed')

  const wireInventory = MASTER_SCHEMA_INVENTORY
    .filter(entry => entry.category === SCHEMA_CATEGORY.WIRE)
    .sort((left, right) => left.categoryLocalSchemaId - right.categoryLocalSchemaId)
  invariant(wireInventory.length === 73, 'current WIRE inventory does not contain 73 rows')
  exactArray(wireInventory.map(entry => entry.schemaName), SCHEMA_NAMES_BY_CATEGORY[SCHEMA_CATEGORY.WIRE],
    'current WIRE inventory order changed')

  const deferred = new Map(PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES.map(name => [
    name,
    wireInventory.find(entry => entry.schemaName === name)
  ]))
  const hop = deferred.get('BlindForwardRouteHopV1')
  const scope = deferred.get('BlindForwardRouteScopeV1')
  invariant(hop && hop.categoryLocalSchemaId === 28 &&
    hop.definitionKind === SCHEMA_DEFINITION_KIND.STANDALONE &&
    hop.compositionDependencies.length === 0,
  'BlindForwardRouteHopV1 candidate metadata changed')
  invariant(scope && scope.categoryLocalSchemaId === 29 &&
    scope.definitionKind === SCHEMA_DEFINITION_KIND.COMPOSITION,
  'BlindForwardRouteScopeV1 candidate metadata changed')
  exactArray(scope.compositionDependencies, ['BlindForwardRouteHopV1'],
    'BlindForwardRouteScopeV1 candidate dependencies changed')

  const deferredSet = new Set(PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES)
  const deferredEdges = wireInventory
    .filter(entry => !deferredSet.has(entry.schemaName))
    .flatMap(entry => entry.compositionDependencies
      .filter(name => deferredSet.has(name))
      .map(name => `${entry.schemaName}->${name}`))
    .sort()
  exactArray(deferredEdges, PUBLISHED_WIRE_V1_DEFERRED_DEPENDENCY_EDGES,
    'retained WIRE schemas have an unexpected dependency on a deferred candidate')

  return {
    audit,
    wireInventory,
    publishedInventory: wireInventory.filter(entry => !deferredSet.has(entry.schemaName))
  }
}

function verifyPublishedCatalog (catalogBytes, masterText, candidateState) {
  let entries
  try {
    entries = decodeSchemaCatalog(catalogBytes, {
      minimum: PUBLISHED_WIRE_V1_AUTHORITY.wireSchemaCount,
      maximum: PUBLISHED_WIRE_V1_AUTHORITY.wireSchemaCount
    })
  } catch (error) {
    drift('published WIRE schema catalog is not canonical', error)
  }
  invariant(b4a.equals(encodeSchemaCatalog(entries, {
    minimum: PUBLISHED_WIRE_V1_AUTHORITY.wireSchemaCount,
    maximum: PUBLISHED_WIRE_V1_AUTHORITY.wireSchemaCount
  }), catalogBytes), 'published WIRE schema catalog does not round trip exactly')

  const knownSchemaNames = new Set(MASTER_SCHEMA_INVENTORY.map(entry => entry.schemaName))
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index]
    const inventory = candidateState.publishedInventory[index]
    const name = b4a.toString(entry.schemaName, 'ascii')
    invariant(inventory && name === inventory.schemaName,
      `published WIRE schema order changed at row ${index + 1}`)
    invariant(entry.category === SCHEMA_CATEGORY.WIRE,
      `published WIRE schema ${name} has the wrong category`)
    // The two candidates were inserted at current inventory IDs 28 and 29.
    // The already-published catalog predates them, so its IDs remain the
    // contiguous historical 1..71 sequence rather than current candidate IDs.
    invariant(entry.categoryLocalSchemaId === index + 1,
      `published WIRE schema ${name} changed its historical category-local ID`)

    let definition
    try {
      definition = decodeCanonical(canonicalSchemaDefinitionV1, entry.canonicalSchemaBytes)
    } catch (error) {
      drift(`published WIRE schema ${name} has invalid canonical definition bytes`, error)
    }
    invariant(b4a.equals(encodeCanonical(canonicalSchemaDefinitionV1, definition),
      entry.canonicalSchemaBytes), `published WIRE schema ${name} does not round trip exactly`)
    invariant(b4a.toString(definition.schemaName, 'ascii') === name,
      `published WIRE schema ${name} definition changed its name`)
    invariant(definition.definitionKind === inventory.definitionKind,
      `published WIRE schema ${name} definition kind changed`)
    const expectedAlias = inventory.aliasOf == null ? null : inventory.aliasOf
    const actualAlias = definition.aliasOf == null ? null : b4a.toString(definition.aliasOf, 'ascii')
    invariant(actualAlias === expectedAlias, `published WIRE schema ${name} alias changed`)

    const declaration = extractDeclaration(masterText, inventory)
    invariant(b4a.equals(definition.sourceDeclaration, declaration),
      `published WIRE schema ${name} no longer matches its stable-master declaration`)
    const declaredDependencies = dependencyNames(declaration, name, knownSchemaNames)
    const expectedDependencies = inventory.compositionDependencies.filter(dependency =>
      !(name === 'BlindForwardHopOpenV1' && dependency === 'BlindForwardRouteScopeV1')).sort()
    const frozenDependencies = definition.compositionDependencies
      .map(value => b4a.toString(value, 'ascii'))
    exactArray(declaredDependencies, expectedDependencies,
      `published WIRE schema ${name} stable-master dependencies changed`)
    exactArray(frozenDependencies, expectedDependencies,
      `published WIRE schema ${name} frozen dependencies changed`)
  }

  return entries
}

function verifyRuntimeAuthorities (root, read, entries) {
  invariant(compareJson(WIRE_RUNTIME_AUTHORITY, PUBLISHED_WIRE_V1_AUTHORITY),
    'generated WIRE runtime authority metadata changed')
  invariant(WIRE_RUNTIME_AUTHORITY_STATUS.releaseReady === true,
    'published WIRE runtime authority is not independently release-ready')
  exactArray(WIRE_RUNTIME_AUTHORITY_STATUS.releaseBlockers, [],
    'published WIRE runtime authority has release blockers')
  invariant(assertWireAuthorityReady() === WIRE_RUNTIME_AUTHORITY_STATUS,
    'published WIRE runtime authority readiness assertion changed')

  const runtimeSource = b4a.toString(canonicalTextBytes(read,
    path.join(root, 'packages/blind-protocol/wire-runtime-authority.js'),
    'published WIRE runtime authority source'), 'utf8')
  invariant(!/^\s*import\s/m.test(runtimeSource),
    'published WIRE runtime authority gained a transitive import')
  for (const name of PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES) {
    invariant(!runtimeSource.includes(name), `published WIRE runtime authority contains ${name}`)
  }

  const expectedNamesByCategory = Object.fromEntries(Object.entries(SCHEMA_NAMES_BY_CATEGORY)
    .map(([category, names]) => [
      category,
      Number(category) === SCHEMA_CATEGORY.WIRE
        ? entries.map(entry => b4a.toString(entry.schemaName, 'ascii'))
        : names
    ]))
  for (const [category, names] of Object.entries(expectedNamesByCategory)) {
    const expectedHashes = names.map(name => hex(blake2b256(b4a.from(name, 'ascii'))))
    exactArray(SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY[category], expectedHashes,
      `published schema-name commitment changed for category ${category}`)
  }
  for (const name of PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES) {
    const candidateHash = hex(blake2b256(b4a.from(name, 'ascii')))
    invariant(!SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY[SCHEMA_CATEGORY.WIRE].includes(candidateHash),
      `published WIRE schema-name commitment contains ${name}`)
  }
}

function verifyVectorClosure (root, read, listWireVectorPaths, manifestBytes, catalogEntries) {
  let manifest
  try {
    manifest = decodeVectorManifest(manifestBytes)
  } catch (error) {
    drift('published WIRE vector manifest is not canonical', error)
  }
  invariant(manifest.length === PUBLISHED_WIRE_V1_AUTHORITY.vectorCount,
    'published WIRE vector count changed')
  for (const [prefix, count] of Object.entries(EXPECTED_VECTOR_PREFIX_COUNTS)) {
    invariant(manifest.filter(entry => entry.path.startsWith(prefix)).length === count,
      `published WIRE vector count changed for ${prefix}`)
  }
  const manifestPaths = manifest.map(entry => entry.path)
  const vectorRoot = path.join(root, 'packages/blind-protocol/vectors')
  let actualPaths
  try {
    actualPaths = safeActualPaths(listWireVectorPaths(vectorRoot))
  } catch (error) {
    if (error && error.code === 'BLIND_PUBLISHED_WIRE_V1_DRIFT') throw error
    drift('could not list the published WIRE vector closure', error)
  }
  exactArray(actualPaths, manifestPaths,
    'published WIRE vector directory has missing or unmanifested files')

  const vectorBytes = new Map()
  for (const row of manifest) {
    const bytes = read(path.join(vectorRoot, ...row.path.split('/')), `WIRE vector ${row.path}`)
    invariant(BigInt(bytes.byteLength) === row.vectorLength,
      `WIRE vector ${row.path} changed length`)
    invariant(b4a.equals(blake2b256(bytes), row.vectorHash),
      `WIRE vector ${row.path} changed hash`)
    vectorBytes.set(row.path, bytes)
  }

  const schemaPaths = manifestPaths.filter(value => value.startsWith('registry/schemas/'))
  const expectedSchemaPaths = catalogEntries.map(entry => {
    const name = b4a.toString(entry.schemaName, 'ascii')
    return `registry/schemas/${String(entry.categoryLocalSchemaId).padStart(3, '0')}-${name}.bin`
  })
  exactArray(schemaPaths, expectedSchemaPaths, 'published WIRE schema vector path set changed')
  for (let index = 0; index < catalogEntries.length; index++) {
    const entry = catalogEntries[index]
    const expected = encodeCanonical(schemaCatalogEntryV1, entry)
    invariant(b4a.equals(vectorBytes.get(expectedSchemaPaths[index]), expected),
      `published WIRE schema vector ${expectedSchemaPaths[index]} changed its catalog row`)
  }
  for (const name of PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES) {
    invariant(!manifestPaths.some(value => value.includes(name)),
      `published WIRE vector manifest contains ${name}`)
  }
  return manifest
}

export function verifyBlindPublishedWireV1 (options = {}) {
  const { root, read, listWireVectorPaths } = normalizedOptions(options)
  const metadata = canonicalJson(read,
    path.join(root, 'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json'),
    PUBLISHED_WIRE_V1_AUTHORITY,
    'published WIRE v1 metadata')
  const specBytes = canonicalTextBytes(read,
    path.join(root, metadata.specArtifact), 'published WIRE v1 specification')
  const masterBytes = canonicalTextBytes(read,
    path.join(root, 'docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md'),
    'stable master specification')
  const masterText = b4a.toString(masterBytes, 'utf8')
  const candidateState = verifyCurrentCandidateState(masterText)

  const abiBytes = read(path.join(root, metadata.abiArtifact), 'published WIRE v1 ABI')
  const abiAliasBytes = read(
    path.join(root, 'packages/blind-protocol/hiverelay-blind-abi-v1.draft.cenc'),
    'published WIRE v1 ABI alias')
  const manifestBytes = read(path.join(root, metadata.vectorManifestArtifact),
    'published WIRE v1 vector manifest')
  const manifestAliasBytes = read(
    path.join(root, 'packages/blind-protocol/vectors/draft/vector-manifest-v1.draft.cenc'),
    'published WIRE v1 vector-manifest alias')
  invariant(b4a.equals(abiBytes, abiAliasBytes), 'published WIRE v1 ABI alias changed')
  invariant(b4a.equals(manifestBytes, manifestAliasBytes),
    'published WIRE v1 vector-manifest alias changed')
  invariant(hex(hashSpec(specBytes)) === metadata.specHash,
    'published WIRE v1 specification hash changed')
  invariant(hex(hashAbi(abiBytes)) === metadata.abiHash,
    'published WIRE v1 ABI hash changed')
  invariant(hex(hashVectorSet(manifestBytes)) === metadata.vectorSetHash,
    'published WIRE v1 vector-set hash changed')

  const catalogBytes = read(
    path.join(root, 'packages/blind-protocol/vectors/registry/wire-schema-catalog.bin'),
    'published WIRE v1 schema catalog')
  const catalogAliasBytes = read(
    path.join(root, 'packages/blind-protocol/vectors/draft/registry/wire-schema-catalog.bin'),
    'published WIRE v1 schema-catalog alias')
  invariant(b4a.equals(catalogBytes, catalogAliasBytes),
    'published WIRE v1 schema-catalog alias changed')
  const catalogEntries = verifyPublishedCatalog(catalogBytes, masterText, candidateState)
  const manifest = verifyVectorClosure(root, read, listWireVectorPaths, manifestBytes, catalogEntries)
  verifyRuntimeAuthorities(root, read, catalogEntries)

  return Object.freeze({
    schema: 'hiverelay-blind-published-wire-v1-verification-v1',
    profile: metadata.profile,
    specHash: metadata.specHash,
    abiHash: metadata.abiHash,
    vectorSetHash: metadata.vectorSetHash,
    publishedWireSchemaCount: catalogEntries.length,
    currentWireInventoryCount: candidateState.wireInventory.length,
    vectorCount: manifest.length,
    deferredSchemaNames: Object.freeze([...PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES]),
    currentReleaseBlockers: Object.freeze([...ABI_STATUS.releaseBlockers])
  })
}

export {
  PUBLISHED_WIRE_V1_AUTHORITY,
  PUBLISHED_WIRE_V1_DEFERRED_DEPENDENCY_EDGES,
  PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES
}
