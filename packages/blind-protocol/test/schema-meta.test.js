import test from 'brittle'
import b4a from 'b4a'
import {
  SCHEMA_DEFINITION_KIND,
  EXECUTABLE_SCHEMA_CODEC_STATUS,
  canonicalSchemaDefinitionV1,
  decodeCanonical,
  decodeSchemaCatalog,
  encodeCanonical,
  encodeSchemaCatalog,
  schemaCatalogEntryV1
} from '../index.js'

const ascii = value => b4a.from(value, 'ascii')

test('schema meta grammar is canonical and category-local catalog rows round trip', t => {
  t.is(EXECUTABLE_SCHEMA_CODEC_STATUS.executableCodecCount, 141)
  t.is(EXECUTABLE_SCHEMA_CODEC_STATUS.privateIpcCodecNames.length, 7)
  t.alike(EXECUTABLE_SCHEMA_CODEC_STATUS.privateIpcLeakNames, [])
  const definition = {
    version: 1,
    definitionKind: SCHEMA_DEFINITION_KIND.COMPOSITION,
    schemaName: ascii('RelayResultBindingV1'),
    sourceDeclaration: ascii('RelayResultBindingV1 {\n  version: u8 = 1\n}'),
    aliasOf: null,
    compositionDependencies: [ascii('BlindExternalCommitWitnessV1')]
  }
  const canonicalSchemaBytes = encodeCanonical(canonicalSchemaDefinitionV1, definition)
  const decodedDefinition = decodeCanonical(canonicalSchemaDefinitionV1, canonicalSchemaBytes)
  t.alike(decodedDefinition.schemaName, definition.schemaName)
  t.alike(decodedDefinition.compositionDependencies, definition.compositionDependencies)

  const entry = {
    category: 1,
    categoryLocalSchemaId: 68,
    schemaName: definition.schemaName,
    canonicalSchemaBytes
  }
  const decodedEntry = decodeCanonical(schemaCatalogEntryV1, encodeCanonical(schemaCatalogEntryV1, entry))
  t.is(decodedEntry.categoryLocalSchemaId, 68)
  const catalog = encodeSchemaCatalog([entry])
  t.is(decodeSchemaCatalog(catalog, { minimum: 1, maximum: 1 }).length, 1)
})

test('schema meta grammar rejects unsorted dependencies, unknown IDs and malformed inline unions', t => {
  const base = {
    version: 1,
    definitionKind: SCHEMA_DEFINITION_KIND.COMPOSITION,
    schemaName: ascii('RelayResultBindingV1'),
    sourceDeclaration: ascii('RelayResultBindingV1 {\n  version: u8 = 1\n}'),
    aliasOf: null,
    compositionDependencies: [ascii('RelayResultBindingV1'), ascii('BlindExternalCommitWitnessV1')]
  }
  t.exception(() => encodeCanonical(canonicalSchemaDefinitionV1, base), /strictly raw-ASCII sorted/)
  t.exception(() => encodeCanonical(schemaCatalogEntryV1, {
    category: 5,
    categoryLocalSchemaId: 1,
    schemaName: ascii('LocalDispatchV1'),
    canonicalSchemaBytes: ascii('x')
  }), /frozen category registry/)
  t.exception(() => encodeCanonical(canonicalSchemaDefinitionV1, {
    ...base,
    definitionKind: SCHEMA_DEFINITION_KIND.INLINE_UNION,
    schemaName: ascii('BatchGetEntryV1'),
    sourceDeclaration: ascii('BatchGetEntryV1 { invalid }'),
    compositionDependencies: []
  }), /explicitly name its tagged union/)
})
