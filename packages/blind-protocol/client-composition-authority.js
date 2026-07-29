import b4a from 'b4a'
import {
  CELL_BLOB_V1_BY_SIZE_CLASS,
  blindCoreReadCapV1,
  opaqueChainCheckpointV1,
  opaqueChainFrameV1,
  readCellCapV1,
  writeCellCapV1
} from './client-internal-schemas.js'
import { decodeCanonical, encodeCanonical } from './codec.js'
import { protocolError } from './errors.js'
import {
  blake2b256,
  decodeVectorManifest,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet
} from './hashes.js'
import { SCHEMA_CATEGORY } from './registry.js'
import { decodeSchemaCatalog, encodeSchemaCatalog } from './schema-meta.js'

const MAGIC = b4a.from('HRBCCF01', 'ascii')
const AUTHORITY_VERSION = 1
const FORMAT_MAJOR = 1
const FORMAT_MINOR = 0
const HEADER_BYTES = 30
const MAX_SPEC_BYTES = 1024 * 1024
const MAX_SCHEMA_CATALOG_BYTES = 1024 * 1024
const HASH_BYTES = 32

export const CLIENT_COMPOSITION_SCHEMA_NAMES_V1 = Object.freeze([
  'BlindCoreReadCapV1',
  'CellBlobV1',
  'OpaqueChainCheckpointV1',
  'OpaqueChainFrameV1',
  'ReadCellCapV1',
  'WriteCellCapV1'
])

function expectation (path, schemaName, outcome, options = {}) {
  return Object.freeze({ path, schemaName, outcome, ...options })
}

export const CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1 = Object.freeze([
  expectation('negative/blind-core-read-cap-zero-core-public-key.bin', 'BlindCoreReadCapV1', 'BAD_ENCODING'),
  expectation('negative/cell-blob-v1-class-1-truncated.bin', 'CellBlobV1', 'BAD_ENCODING', { sizeClass: 1 }),
  expectation('negative/opaque-chain-checkpoint-unsorted-frontier.bin', 'OpaqueChainCheckpointV1', 'BAD_ENCODING'),
  expectation('negative/opaque-chain-frame-sequence-one-without-predecessor.bin', 'OpaqueChainFrameV1', 'BAD_ENCODING'),
  expectation('negative/read-cell-cap-zero-relay-public-key.bin', 'ReadCellCapV1', 'BAD_ENCODING'),
  expectation('negative/write-cell-cap-duplicate-private-keys.bin', 'WriteCellCapV1', 'BAD_ENCODING'),
  expectation('positive/blind-core-read-cap-v1.bin', 'BlindCoreReadCapV1', 'ACCEPT'),
  expectation('positive/cell-blob-v1-class-1.bin', 'CellBlobV1', 'ACCEPT', { sizeClass: 1 }),
  expectation('positive/cell-blob-v1-class-2.bin', 'CellBlobV1', 'ACCEPT', { sizeClass: 2 }),
  expectation('positive/cell-blob-v1-class-3.bin', 'CellBlobV1', 'ACCEPT', { sizeClass: 3 }),
  expectation('positive/cell-blob-v1-class-4.bin', 'CellBlobV1', 'ACCEPT', { sizeClass: 4 }),
  expectation('positive/cell-blob-v1-class-5.bin', 'CellBlobV1', 'ACCEPT', { sizeClass: 5 }),
  expectation('positive/opaque-chain-checkpoint-v1.bin', 'OpaqueChainCheckpointV1', 'ACCEPT'),
  expectation('positive/opaque-chain-frame-v1-genesis.bin', 'OpaqueChainFrameV1', 'ACCEPT'),
  expectation('positive/opaque-chain-frame-v1-successor.bin', 'OpaqueChainFrameV1', 'ACCEPT'),
  expectation('positive/read-cell-cap-v1.bin', 'ReadCellCapV1', 'ACCEPT'),
  expectation('positive/write-cell-cap-v1.bin', 'WriteCellCapV1', 'ACCEPT'),
  expectation('registry/client-composition-schema-catalog-v1.cenc', null, 'CATALOG')
])

const verifiedAuthorities = new WeakSet()

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isSharedArrayBuffer (value) {
  return typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer
}

function copyBytes (value, field) {
  if (value instanceof ArrayBuffer) return b4a.from(value.slice(0))
  if (ArrayBuffer.isView(value)) {
    if (isSharedArrayBuffer(value.buffer)) fail(`${field} cannot use shared memory`)
    return b4a.from(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength))
  }
  fail(`${field} must be ArrayBuffer-backed bytes`)
}

function fixedHash (value, field) {
  const bytes = copyBytes(value, field)
  if (bytes.byteLength !== HASH_BYTES) fail(`${field} must be exactly ${HASH_BYTES} bytes`)
  return bytes
}

function readU16 (bytes, offset) {
  return bytes[offset] * 0x100 + bytes[offset + 1]
}

function readU64 (bytes, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(bytes[offset + index])
  return value
}

function writeU16 (bytes, value, offset) {
  bytes[offset] = value >>> 8
  bytes[offset + 1] = value
}

function writeU64 (bytes, value, offset) {
  value = BigInt(value)
  for (let index = 7; index >= 0; index--) {
    bytes[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function validateSpecBytes (input) {
  const bytes = copyBytes(input, 'client-composition specification')
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SPEC_BYTES) {
    fail(`client-composition specification length is outside 1..${MAX_SPEC_BYTES}`)
  }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail('client-composition specification must not have a UTF-8 BOM')
  }
  for (const byte of bytes) {
    if (byte === 0 || byte === 0x0d) fail('client-composition specification must use NUL-free LF-only UTF-8')
  }
  const text = b4a.toString(bytes, 'utf8')
  if (!b4a.equals(b4a.from(text, 'utf8'), bytes)) fail('client-composition specification is not strict UTF-8')
  if (!text.endsWith('\n') || text.endsWith('\n\n')) {
    fail('client-composition specification must end in exactly one LF')
  }
  return bytes
}

function validateSchemaCatalogBytes (input) {
  const bytes = copyBytes(input, 'client-composition schema catalog')
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SCHEMA_CATALOG_BYTES) {
    fail(`client-composition schema catalog length is outside 1..${MAX_SCHEMA_CATALOG_BYTES}`)
  }
  const entries = decodeSchemaCatalog(bytes, {
    minimum: CLIENT_COMPOSITION_SCHEMA_NAMES_V1.length,
    maximum: CLIENT_COMPOSITION_SCHEMA_NAMES_V1.length,
    name: 'client-composition schema catalog'
  })
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index]
    if (entry.category !== SCHEMA_CATEGORY.CLIENT_EXAMPLE || entry.categoryLocalSchemaId !== index + 1 ||
        b4a.toString(entry.schemaName, 'ascii') !== CLIENT_COMPOSITION_SCHEMA_NAMES_V1[index]) {
      fail('client-composition schema catalog contains a foreign, reordered, or renumbered schema')
    }
  }
  const canonical = encodeSchemaCatalog(entries, {
    minimum: CLIENT_COMPOSITION_SCHEMA_NAMES_V1.length,
    maximum: CLIENT_COMPOSITION_SCHEMA_NAMES_V1.length,
    name: 'client-composition schema catalog'
  })
  if (!b4a.equals(canonical, bytes)) fail('client-composition schema catalog is not canonical')
  return { bytes, entries }
}

export function encodeClientCompositionFormatAuthorityV1 (specBytes, schemaCatalogBytes) {
  const spec = validateSpecBytes(specBytes)
  const catalog = validateSchemaCatalogBytes(schemaCatalogBytes).bytes
  const output = b4a.alloc(HEADER_BYTES + spec.byteLength + catalog.byteLength)
  b4a.copy(MAGIC, output, 0)
  writeU16(output, AUTHORITY_VERSION, 8)
  writeU16(output, FORMAT_MAJOR, 10)
  writeU16(output, FORMAT_MINOR, 12)
  writeU64(output, spec.byteLength, 14)
  writeU64(output, catalog.byteLength, 22)
  b4a.copy(spec, output, HEADER_BYTES)
  b4a.copy(catalog, output, HEADER_BYTES + spec.byteLength)
  return output
}

export function decodeClientCompositionFormatAuthorityV1 (input) {
  const bytes = copyBytes(input, 'client-composition format artifact')
  if (bytes.byteLength < HEADER_BYTES + 2 || !b4a.equals(bytes.subarray(0, 8), MAGIC)) {
    fail('client-composition format artifact has invalid magic or is truncated')
  }
  const authorityVersion = readU16(bytes, 8)
  const formatMajor = readU16(bytes, 10)
  const formatMinor = readU16(bytes, 12)
  if (authorityVersion !== AUTHORITY_VERSION || formatMajor !== FORMAT_MAJOR || formatMinor !== FORMAT_MINOR) {
    fail('client-composition format artifact has an unsupported version')
  }
  const specLength = readU64(bytes, 14)
  const catalogLength = readU64(bytes, 22)
  if (specLength === 0n || specLength > BigInt(MAX_SPEC_BYTES) ||
      catalogLength === 0n || catalogLength > BigInt(MAX_SCHEMA_CATALOG_BYTES)) {
    fail('client-composition format artifact has an invalid component length')
  }
  const expectedLength = BigInt(HEADER_BYTES) + specLength + catalogLength
  if (expectedLength !== BigInt(bytes.byteLength)) {
    fail(expectedLength > BigInt(bytes.byteLength)
      ? 'client-composition format artifact is truncated'
      : 'client-composition format artifact has trailing bytes')
  }
  const specEnd = HEADER_BYTES + Number(specLength)
  const specBytes = validateSpecBytes(bytes.subarray(HEADER_BYTES, specEnd))
  const catalog = validateSchemaCatalogBytes(bytes.subarray(specEnd))
  return Object.freeze({
    authorityVersion,
    formatMajor,
    formatMinor,
    specBytes,
    schemaCatalogBytes: catalog.bytes,
    schemaCatalogEntries: Object.freeze(catalog.entries)
  })
}

export function verifyClientCompositionFormatAuthorityV1 (input, options = {}) {
  const authorityBytes = copyBytes(input, 'client-composition format artifact')
  const decoded = decodeClientCompositionFormatAuthorityV1(authorityBytes)
  const canonical = encodeClientCompositionFormatAuthorityV1(decoded.specBytes, decoded.schemaCatalogBytes)
  if (!b4a.equals(canonical, authorityBytes)) fail('client-composition format artifact is not canonical')
  if (options.specBytes != null && !b4a.equals(validateSpecBytes(options.specBytes), decoded.specBytes)) {
    fail('client-composition format artifact does not contain the expected specification')
  }
  if (options.schemaCatalogBytes != null &&
      !b4a.equals(validateSchemaCatalogBytes(options.schemaCatalogBytes).bytes, decoded.schemaCatalogBytes)) {
    fail('client-composition format artifact does not contain the expected schema catalog')
  }
  const formatHash = hashClientCompositionFormat(authorityBytes)
  if (options.expectedFormatHash != null &&
      !b4a.equals(fixedHash(options.expectedFormatHash, 'expected client-composition format hash'), formatHash)) {
    fail('client-composition format artifact does not match the expected format hash')
  }
  return Object.freeze({
    authorityVersion: decoded.authorityVersion,
    formatMajor: decoded.formatMajor,
    formatMinor: decoded.formatMinor,
    authorityBytes,
    specBytes: decoded.specBytes,
    schemaCatalogBytes: decoded.schemaCatalogBytes,
    schemaCatalogEntries: decoded.schemaCatalogEntries,
    formatHash
  })
}

function vectorMap (vectors) {
  const output = new Map()
  if (vectors instanceof Map) {
    for (const [path, bytes] of Map.prototype.entries.call(vectors)) {
      if (typeof path !== 'string' || output.has(path)) fail('client-composition vector map has an invalid path')
      output.set(path, copyBytes(bytes, `client-composition vector ${path}`))
    }
    return output
  }
  if (vectors == null || typeof vectors !== 'object' ||
      (Object.getPrototypeOf(vectors) !== Object.prototype && Object.getPrototypeOf(vectors) !== null)) {
    fail('client-composition vectors must be a Map or plain data object')
  }
  for (const key of Reflect.ownKeys(vectors)) {
    if (typeof key !== 'string') fail('client-composition vector map must not have symbol keys')
    const descriptor = Object.getOwnPropertyDescriptor(vectors, key)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('client-composition vector map must not use accessors')
    output.set(key, copyBytes(descriptor.value, `client-composition vector ${key}`))
  }
  return output
}

function codecFor (expectation) {
  if (expectation.schemaName === 'CellBlobV1') return CELL_BLOB_V1_BY_SIZE_CLASS[expectation.sizeClass]
  return {
    BlindCoreReadCapV1: blindCoreReadCapV1,
    OpaqueChainCheckpointV1: opaqueChainCheckpointV1,
    OpaqueChainFrameV1: opaqueChainFrameV1,
    ReadCellCapV1: readCellCapV1,
    WriteCellCapV1: writeCellCapV1
  }[expectation.schemaName]
}

function verifyVectorSemantics (expectation, bytes, schemaCatalogBytes) {
  if (expectation.outcome === 'CATALOG') {
    if (!b4a.equals(bytes, schemaCatalogBytes)) fail('client-composition registry vector differs from the format catalog')
    validateSchemaCatalogBytes(bytes)
    return
  }
  const codec = codecFor(expectation)
  if (!codec) fail(`client-composition vector ${expectation.path} has no codec`)
  if (expectation.outcome === 'ACCEPT') {
    const decoded = decodeCanonical(codec, bytes, { copyBytes: true })
    const encoded = encodeCanonical(codec, decoded)
    if (!b4a.equals(encoded, bytes)) fail(`client-composition vector ${expectation.path} is not byte-reproducible`)
    return
  }
  let error = null
  try {
    decodeCanonical(codec, bytes, { copyBytes: true })
  } catch (cause) {
    error = cause
  }
  if (!error || error.code !== expectation.outcome) {
    fail(`client-composition negative vector ${expectation.path} did not fail with ${expectation.outcome}`)
  }
}

export function verifyClientCompositionVectorSetV1 (manifestInput, vectors, options = {}) {
  const manifestBytes = copyBytes(manifestInput, 'client-composition vector manifest')
  const schemaCatalogBytes = validateSchemaCatalogBytes(options.schemaCatalogBytes).bytes
  const entries = decodeVectorManifest(manifestBytes)
  const supplied = vectorMap(vectors)
  if (entries.length !== CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.length ||
      supplied.size !== CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.length) {
    fail('client-composition vector set has a missing or extra entry')
  }
  for (let index = 0; index < CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1.length; index++) {
    const expected = CLIENT_COMPOSITION_VECTOR_EXPECTATIONS_V1[index]
    const entry = entries[index]
    if (entry.path !== expected.path || !supplied.has(expected.path)) {
      fail('client-composition vector manifest does not match its closed path inventory')
    }
    const bytes = supplied.get(expected.path)
    if (entry.vectorLength !== BigInt(bytes.byteLength) || !b4a.equals(entry.vectorHash, blake2b256(bytes))) {
      fail(`client-composition vector ${expected.path} does not match its manifest row`)
    }
    verifyVectorSemantics(expected, bytes, schemaCatalogBytes)
  }
  const vectorSetHash = hashClientCompositionVectorSet(manifestBytes)
  if (options.expectedVectorSetHash != null &&
      !b4a.equals(fixedHash(options.expectedVectorSetHash, 'expected client-composition vector-set hash'), vectorSetHash)) {
    fail('client-composition vector manifest does not match the expected vector-set hash')
  }
  return Object.freeze({
    manifestBytes,
    entries,
    vectorSetHash,
    vectorCount: entries.length
  })
}

export function verifyClientCompositionAuthorityV1 (input) {
  if (input == null || typeof input !== 'object') fail('client-composition authority input must be an object')
  if (input.expectedFormatHash == null || input.expectedVectorSetHash == null) {
    fail('complete client-composition authority verification requires both expected hash pins')
  }
  const format = verifyClientCompositionFormatAuthorityV1(input.formatAuthorityBytes, {
    specBytes: input.specBytes,
    schemaCatalogBytes: input.schemaCatalogBytes,
    expectedFormatHash: input.expectedFormatHash
  })
  const vectors = verifyClientCompositionVectorSetV1(input.vectorManifestBytes, input.vectors, {
    schemaCatalogBytes: format.schemaCatalogBytes,
    expectedVectorSetHash: input.expectedVectorSetHash
  })
  const verified = Object.freeze({
    profile: 'client-composition-authority-v1',
    formatMajor: format.formatMajor,
    formatMinor: format.formatMinor,
    formatHash: b4a.from(format.formatHash),
    vectorSetHash: b4a.from(vectors.vectorSetHash),
    schemaNames: CLIENT_COMPOSITION_SCHEMA_NAMES_V1,
    vectorCount: vectors.vectorCount
  })
  verifiedAuthorities.add(verified)
  return verified
}

export function isVerifiedClientCompositionAuthorityV1 (value) {
  return value != null && typeof value === 'object' && verifiedAuthorities.has(value)
}

export const CLIENT_COMPOSITION_FORMAT_LAYOUT_V1 = Object.freeze({
  magic: 'HRBCCF01',
  authorityVersion: AUTHORITY_VERSION,
  formatMajor: FORMAT_MAJOR,
  formatMinor: FORMAT_MINOR,
  headerBytes: HEADER_BYTES,
  maximumSpecBytes: MAX_SPEC_BYTES,
  maximumSchemaCatalogBytes: MAX_SCHEMA_CATALOG_BYTES
})
