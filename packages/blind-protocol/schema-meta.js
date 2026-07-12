import b4a from 'b4a'
import {
  arrayOf,
  canonicalAsciiBytes,
  canonicalUtf8Bytes,
  constant,
  decodeCanonical,
  encodeCanonical,
  optional,
  ranged,
  struct,
  u8
} from './codec.js'
import { protocolError } from './errors.js'
import {
  MASTER_SCHEMA_INVENTORY,
  SCHEMA_DEFINITION_KIND,
  assertMasterSchemaInventory
} from './master-schema-inventory.js'
import { SCHEMA_CATEGORY } from './registry.js'
import { schemaCatalogEntryV1 } from './schemas.js'

const version1 = constant(u8, 1, 'version')
const schemaName = canonicalAsciiBytes(1, 96, 'schemaName')

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function compareBytes (left, right) {
  return b4a.compare(left, right)
}

function assertSortedNames (values, name) {
  for (let index = 1; index < values.length; index++) {
    if (compareBytes(values[index - 1], values[index]) >= 0) {
      fail(`${name} must be strictly raw-ASCII sorted and duplicate-free`)
    }
  }
}

// This is the closed meta-grammar carried inside
// SchemaCatalogEntryV1.canonicalSchemaBytes. The source declaration is the exact
// fenced declaration from the stable master, not JavaScript source metadata.
export const canonicalSchemaDefinitionV1 = struct([
  ['version', version1],
  ['definitionKind', ranged(u8, 1, 4, 'definitionKind')],
  ['schemaName', schemaName],
  ['sourceDeclaration', canonicalUtf8Bytes(1, 0xffff, 'sourceDeclaration')],
  ['aliasOf', optional(schemaName, 'aliasOf')],
  ['compositionDependencies', arrayOf(schemaName, 0, 64, 'compositionDependencies')]
], {
  name: 'CanonicalSchemaDefinitionV1',
  validate (value) {
    assertSortedNames(value.compositionDependencies, 'compositionDependencies')
    if (value.aliasOf != null && value.definitionKind !== SCHEMA_DEFINITION_KIND.COMPOSITION) {
      fail('aliasOf is allowed only on a composition definition')
    }
    if (value.definitionKind === SCHEMA_DEFINITION_KIND.INLINE_UNION &&
        !b4a.toString(value.sourceDeclaration, 'utf8').includes('tagged union')) {
      fail('inline union source declaration must explicitly name its tagged union')
    }
  }
})

function extractDeclaration (canonicalMasterText, schemaName, definitionKind) {
  const escaped = schemaName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const header = definitionKind === SCHEMA_DEFINITION_KIND.INLINE_UNION
    ? new RegExp(`^${escaped}\\s*=\\s*tagged union\\s*\\{`, 'm')
    : new RegExp(`^${escaped}\\s*\\{`, 'm')
  const match = header.exec(canonicalMasterText)
  if (!match) throw new Error(`missing stable-master declaration for ${schemaName}`)
  let depth = 0
  let closing = -1
  for (let index = match.index; index < canonicalMasterText.length; index++) {
    const character = canonicalMasterText[index]
    if (character === '{') depth++
    if (character === '}') {
      depth--
      if (depth === 0) {
        closing = index + 1
        break
      }
    }
  }
  if (closing < 0) throw new Error(`unterminated stable-master declaration for ${schemaName}`)
  const declaration = canonicalMasterText.slice(match.index, closing)
  if (declaration.includes('\r') || declaration.endsWith('\n')) {
    throw new Error(`non-canonical source declaration extraction for ${schemaName}`)
  }
  return b4a.from(declaration, 'utf8')
}

function declarationCount (canonicalMasterText, schemaName, definitionKind) {
  const escaped = schemaName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const source = definitionKind === SCHEMA_DEFINITION_KIND.INLINE_UNION
    ? `^${escaped}\\s*=\\s*tagged union\\s*\\{`
    : `^${escaped}\\s*\\{`
  return (canonicalMasterText.match(new RegExp(source, 'gm')) || []).length
}

function compileInventoryCatalog (canonicalMasterText, inventoryEntries, inventoryAudit) {
  const knownSchemaNames = new Set(MASTER_SCHEMA_INVENTORY.map(entry => entry.schemaName))
  const definitions = []
  const entries = []
  const canonicalSchemaBytesByName = new Map()

  for (const inventory of inventoryEntries) {
    const sourceDeclaration = extractDeclaration(canonicalMasterText, inventory.schemaName, inventory.definitionKind)
    const declaredDependencies = [...new Set((b4a.toString(sourceDeclaration, 'utf8')
      .match(/\b[A-Za-z][A-Za-z0-9]*V1\b/g) || [])
      .filter(name => name !== inventory.schemaName && knownSchemaNames.has(name)))].sort()
    if (declaredDependencies.join('\0') !== [...inventory.compositionDependencies].sort().join('\0')) {
      throw new Error(`composition dependency rules drifted for ${inventory.schemaName}: declared=${declaredDependencies.join(',')} catalog=${inventory.compositionDependencies.join(',')}`)
    }
    const value = {
      version: 1,
      definitionKind: inventory.definitionKind,
      schemaName: b4a.from(inventory.schemaName, 'ascii'),
      sourceDeclaration,
      aliasOf: inventory.aliasOf == null ? null : b4a.from(inventory.aliasOf, 'ascii'),
      compositionDependencies: inventory.compositionDependencies
        .map(name => b4a.from(name, 'ascii'))
        .sort(compareBytes)
    }
    const canonicalSchemaBytes = encodeCanonical(canonicalSchemaDefinitionV1, value)
    if (canonicalSchemaBytes.byteLength > 0xffff) throw new Error(`${inventory.schemaName} meta definition exceeds 65535 bytes`)
    const decoded = decodeCanonical(canonicalSchemaDefinitionV1, canonicalSchemaBytes)
    if (b4a.toString(decoded.schemaName, 'ascii') !== inventory.schemaName) {
      throw new Error(`schema meta round trip changed ${inventory.schemaName}`)
    }
    const entry = {
      category: inventory.category,
      categoryLocalSchemaId: inventory.categoryLocalSchemaId,
      schemaName: b4a.from(inventory.schemaName, 'ascii'),
      canonicalSchemaBytes
    }
    // Exercise the public catalog codec while compiling, including PRIVATE_IPC
    // rows. This validates category-local IDs without taking codec ownership.
    decodeCanonical(schemaCatalogEntryV1, encodeCanonical(schemaCatalogEntryV1, entry))
    definitions.push(value)
    entries.push(entry)
    canonicalSchemaBytesByName.set(inventory.schemaName, canonicalSchemaBytes)
  }

  const duplicateDefinitionBytes = []
  const hashes = new Map()
  for (const entry of entries) {
    const key = b4a.toString(entry.canonicalSchemaBytes, 'hex')
    if (hashes.has(key)) duplicateDefinitionBytes.push(`${hashes.get(key)}=${b4a.toString(entry.schemaName, 'ascii')}`)
    hashes.set(key, b4a.toString(entry.schemaName, 'ascii'))
  }
  if (duplicateDefinitionBytes.length > 0) throw new Error(`duplicate canonical schema definitions: ${duplicateDefinitionBytes.join(', ')}`)

  return Object.freeze({
    inventoryAudit,
    definitions: Object.freeze(definitions),
    entries: Object.freeze(entries),
    canonicalSchemaBytesByName
  })
}

export function compileMasterSchemaCatalog (canonicalMasterText) {
  const inventoryAudit = assertMasterSchemaInventory(canonicalMasterText)
  return compileInventoryCatalog(canonicalMasterText, MASTER_SCHEMA_INVENTORY, inventoryAudit)
}

export function compileMasterSchemaCatalogForCategory (canonicalMasterText, category) {
  if (!Object.values(SCHEMA_CATEGORY).includes(category)) throw new TypeError('unknown schema category')
  const inventoryEntries = MASTER_SCHEMA_INVENTORY.filter(entry => entry.category === category)
  const missingSchemaNames = []
  const duplicateSchemaNames = []
  for (const inventory of inventoryEntries) {
    const count = declarationCount(canonicalMasterText, inventory.schemaName, inventory.definitionKind)
    if (count === 0) missingSchemaNames.push(inventory.schemaName)
    if (count > 1) duplicateSchemaNames.push(inventory.schemaName)
  }
  if (missingSchemaNames.length > 0 || duplicateSchemaNames.length > 0) {
    const error = new Error('master schema category does not match its executable inventory')
    error.code = 'BLIND_MASTER_SCHEMA_CATEGORY_MISMATCH'
    error.category = category
    error.missingSchemaNames = missingSchemaNames
    error.duplicateSchemaNames = duplicateSchemaNames
    throw error
  }
  const inventoryAudit = Object.freeze({
    ok: true,
    category,
    catalogSchemaCount: inventoryEntries.length,
    missingSchemaNames: Object.freeze([]),
    duplicateSchemaNames: Object.freeze([])
  })
  return compileInventoryCatalog(canonicalMasterText, inventoryEntries, inventoryAudit)
}

export function schemaCatalogEncoding (minimum, maximum, name = 'schema catalog') {
  return arrayOf(schemaCatalogEntryV1, minimum, maximum, name)
}

export function encodeSchemaCatalog (entries, options = {}) {
  const minimum = options.minimum == null ? entries.length : options.minimum
  const maximum = options.maximum == null ? entries.length : options.maximum
  return encodeCanonical(schemaCatalogEncoding(minimum, maximum, options.name), entries)
}

export function decodeSchemaCatalog (bytes, options = {}) {
  const minimum = options.minimum == null ? 0 : options.minimum
  const maximum = options.maximum == null ? 0xffff : options.maximum
  const entries = decodeCanonical(schemaCatalogEncoding(minimum, maximum, options.name), bytes)
  const names = new Set()
  const ids = new Set()
  for (const entry of entries) {
    const name = b4a.toString(entry.schemaName, 'ascii')
    const id = `${entry.category}:${entry.categoryLocalSchemaId}`
    if (names.has(name) || ids.has(id)) fail('schema catalog contains a duplicate name or category-local ID')
    names.add(name)
    ids.add(id)
  }
  return entries
}
