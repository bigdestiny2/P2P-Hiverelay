import {
  closeSync,
  constants as FS_CONSTANTS,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync
} from 'fs'
import { createHash } from 'crypto'
import { isAbsolute, normalize, relative, resolve, sep } from 'path'
import {
  CORESTORE_GENERATION_CAPABILITIES,
  CORESTORE_GENERATION_ENVELOPE,
  CORESTORE_GENERATION_MIGRATION_BINDING,
  corestoreGenerationOpenOptions
} from './corestore-generation-envelope.js'

export const STORAGE_GENERATION_RECEIPT = Object.freeze({
  maxBytes: 64 * 1024,
  receiptEnvironment: 'HIVERELAY_GENERATION_RECEIPT',
  receiptSha256Environment: 'HIVERELAY_GENERATION_RECEIPT_SHA256',
  receiptSha256FileEnvironment: 'HIVERELAY_GENERATION_RECEIPT_SHA256_FILE',
  requiredEnvironment: 'HIVERELAY_REQUIRE_GENERATION_RECEIPT'
})

const RECEIPT_KEYS = Object.freeze([
  'authorityKeySha256',
  'generation',
  'generationRoot',
  'installationId',
  'manifestSha256',
  'migrationTooling',
  'mode',
  'oldWriterFenceScope',
  'participants',
  'schema',
  'topLevelSidecars'
])
const MIGRATION_BINDING_KEYS = Object.freeze(Object.keys(CORESTORE_GENERATION_MIGRATION_BINDING).sort(compareCodeUnits))
const DIGEST = /^sha256:[0-9a-f]{64}$/
const HEX_32 = /^[0-9a-f]{64}$/
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

export class StorageGenerationReceiptError extends Error {
  constructor (message, code = 'CORESTORE_GENERATION_RECEIPT_INVALID') {
    super(message)
    this.name = 'StorageGenerationReceiptError'
    this.code = code
  }
}

/**
 * Parse the unique canonical byte encoding of an offline generation receipt.
 * The caller must provide a separately transported SHA-256 pin; receipt fields
 * are never accepted merely because they are internally well formed.
 */
export function parseCorestoreGenerationReceiptBytes (bytes, {
  expectedSha256,
  participant
} = {}) {
  bytes = Buffer.from(bytes || [])
  if (bytes.byteLength < 2 || bytes.byteLength > STORAGE_GENERATION_RECEIPT.maxBytes) {
    fail(`generation receipt must contain 2..${STORAGE_GENERATION_RECEIPT.maxBytes} bytes`)
  }
  expectedSha256 = exactDigest(expectedSha256, 'generation receipt SHA-256 pin')
  const receiptSha256 = sha256(bytes)
  if (receiptSha256 !== expectedSha256) {
    fail('generation receipt bytes do not match the external SHA-256 pin', 'CORESTORE_GENERATION_RECEIPT_PIN_MISMATCH')
  }

  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes)) fail('generation receipt is not valid UTF-8')
  let receipt
  try {
    receipt = JSON.parse(text)
  } catch {
    fail('generation receipt is not valid JSON')
  }
  receipt = validateReceipt(receipt, participant)
  if (!canonicalBytes(receipt).equals(bytes)) {
    fail('generation receipt is not the unique canonical JSON encoding')
  }
  return Object.freeze({
    receipt,
    receiptSha256,
    hiverelayGeneration: corestoreGenerationOpenOptions(receipt)
  })
}

/**
 * Read an exact receipt from an external regular file without following a
 * final-component symlink. The receipt and optional pin file must sit outside
 * the mutable Corestore generation root.
 */
export function readCorestoreGenerationReceipt (receiptPath, {
  expectedSha256,
  expectedSha256File,
  participant,
  storageRoot
} = {}) {
  receiptPath = canonicalAbsolute(receiptPath, 'generation receipt path')
  assertOutsideStorage(receiptPath, storageRoot, 'generation receipt')

  let pinFromFile = null
  if (expectedSha256File != null) {
    expectedSha256File = canonicalAbsolute(expectedSha256File, 'generation receipt SHA-256 pin file path')
    if (expectedSha256File === receiptPath) fail('generation receipt and SHA-256 pin file must be distinct')
    assertOutsideStorage(expectedSha256File, storageRoot, 'generation receipt SHA-256 pin file')
    const pinBytes = readRegularFile(expectedSha256File, 'generation receipt SHA-256 pin file', 72)
    if (pinBytes.byteLength !== 72 || pinBytes[71] !== 0x0a) {
      fail('generation receipt SHA-256 pin file must contain one canonical sha256:<hex> line')
    }
    pinFromFile = exactDigest(pinBytes.subarray(0, 71).toString('ascii'), 'generation receipt SHA-256 pin file')
  }

  if (expectedSha256 != null) expectedSha256 = exactDigest(expectedSha256, 'generation receipt SHA-256 pin')
  if (expectedSha256 && pinFromFile && expectedSha256 !== pinFromFile) {
    fail('generation receipt direct and file SHA-256 pins disagree', 'CORESTORE_GENERATION_RECEIPT_PIN_MISMATCH')
  }
  const pin = expectedSha256 || pinFromFile
  if (!pin) fail('generation receipt requires an external SHA-256 pin', 'CORESTORE_GENERATION_RECEIPT_PIN_REQUIRED')

  const parsed = parseCorestoreGenerationReceiptBytes(
    readRegularFile(receiptPath, 'generation receipt', STORAGE_GENERATION_RECEIPT.maxBytes),
    { expectedSha256: pin, participant }
  )
  return Object.freeze({
    ...parsed,
    receiptPath,
    expectedSha256File: expectedSha256File || null,
    pinSource: expectedSha256 ? (pinFromFile ? 'direct-and-file' : 'direct') : 'file'
  })
}

/**
 * Resolve the production launcher contract. A required launcher never falls
 * back to persisted config or hiverelayGeneration:null; a partial receipt
 * declaration also fails closed even when the launcher itself is optional.
 */
export function resolveCorestoreGenerationReceiptLaunch ({
  required = false,
  receiptPath,
  expectedSha256,
  expectedSha256File,
  participant,
  storageRoot
} = {}) {
  if (typeof required !== 'boolean') throw new TypeError('generation receipt required flag must be boolean')
  const declared = [receiptPath, expectedSha256, expectedSha256File].some(value => value != null && value !== '')
  if (!declared) {
    if (required) {
      fail('production startup requires an exact external generation receipt and SHA-256 pin',
        'CORESTORE_GENERATION_RECEIPT_REQUIRED')
    }
    return null
  }
  if (typeof receiptPath !== 'string' || receiptPath.length === 0) {
    fail('generation receipt path is required when any receipt input is declared',
      'CORESTORE_GENERATION_RECEIPT_REQUIRED')
  }
  if ((expectedSha256 == null || expectedSha256 === '') &&
      (expectedSha256File == null || expectedSha256File === '')) {
    fail('generation receipt requires a direct SHA-256 pin or an external pin file',
      'CORESTORE_GENERATION_RECEIPT_PIN_REQUIRED')
  }
  return readCorestoreGenerationReceipt(receiptPath, {
    expectedSha256: expectedSha256 || null,
    expectedSha256File: expectedSha256File || null,
    participant,
    storageRoot
  })
}

export function corestoreGenerationReceiptBytes (receipt) {
  return canonicalBytes(validateReceipt(receipt, null))
}

export function parseGenerationReceiptRequiredEnvironment (value) {
  if (value == null || value === '') return false
  value = String(value).trim().toLowerCase()
  if (value === '1' || value === 'true') return true
  if (value === '0' || value === 'false') return false
  fail(`${STORAGE_GENERATION_RECEIPT.requiredEnvironment} must be 1, true, 0, or false`,
    'CORESTORE_GENERATION_RECEIPT_REQUIRED_FLAG_INVALID')
}

function validateReceipt (receipt, participant) {
  exactObject(receipt, RECEIPT_KEYS, 'generation receipt')
  if (receipt.schema !== CORESTORE_GENERATION_ENVELOPE.schema ||
      receipt.mode !== CORESTORE_GENERATION_ENVELOPE.mode ||
      receipt.generation !== CORESTORE_GENERATION_ENVELOPE.generation ||
      receipt.generationRoot !== CORESTORE_GENERATION_ENVELOPE.generationRoot ||
      receipt.oldWriterFenceScope !== CORESTORE_GENERATION_CAPABILITIES.oldWriterFenceScope) {
    fail('generation receipt does not name the accepted HC11 envelope contract')
  }
  if (typeof receipt.installationId !== 'string' || !HEX_32.test(receipt.installationId)) {
    fail('generation receipt installationId must be 32-byte lowercase hex')
  }
  exactDigest(receipt.authorityKeySha256, 'generation receipt authorityKeySha256')
  exactDigest(receipt.manifestSha256, 'generation receipt manifestSha256')
  const participants = exactNames(receipt.participants, 'generation receipt participants', 1, 32)
  const topLevelSidecars = exactNames(receipt.topLevelSidecars, 'generation receipt topLevelSidecars', 0, 128)
  exactObject(receipt.migrationTooling, MIGRATION_BINDING_KEYS, 'generation receipt migrationTooling')
  if (!canonicalBytes(receipt.migrationTooling).equals(canonicalBytes(CORESTORE_GENERATION_MIGRATION_BINDING))) {
    fail('generation receipt migrationTooling does not match the accepted storage-generation binding')
  }
  if (participant != null) {
    if (typeof participant !== 'string' || !SAFE_NAME.test(participant)) throw new TypeError('generation participant is invalid')
    if (!participants.includes(participant)) {
      fail(`generation receipt does not authorize runtime participant ${participant}`,
        'CORESTORE_GENERATION_PARTICIPANT_MISSING')
    }
  }
  return deepFreeze({
    ...receipt,
    participants: [...participants],
    topLevelSidecars: [...topLevelSidecars],
    migrationTooling: { ...receipt.migrationTooling }
  })
}

function exactNames (value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    fail(`${label} must contain ${minimum}..${maximum} entries`)
  }
  const names = value.map(name => {
    if (typeof name !== 'string' || !SAFE_NAME.test(name) || name === '.' || name === '..') {
      fail(`${label} contains an unsafe name`)
    }
    return name
  })
  if (new Set(names).size !== names.length) fail(`${label} contains duplicate entries`)
  const sorted = [...names].sort(compareCodeUnits)
  if (!sameStrings(names, sorted)) fail(`${label} must use code-unit order`)
  return names
}

function exactObject (value, keys, label) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`)
  const actual = Object.keys(value).sort(compareCodeUnits)
  if (!sameStrings(actual, keys)) fail(`${label} fields do not match the closed schema`)
}

function readRegularFile (file, label, maximum) {
  let descriptor
  try {
    const lstat = lstatSync(file)
    if (lstat.isSymbolicLink()) fail(`${label} must not be a symbolic link`)
    assertRuntimeReadOnly(file, label)
    const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0)
    descriptor = openSync(file, flags)
    const stat = fstatSync(descriptor)
    if (!stat.isFile()) fail(`${label} must be a regular file`)
    if (stat.size < 1 || stat.size > maximum) fail(`${label} must contain 1..${maximum} bytes`)
    const bytes = readFileSync(descriptor)
    if (bytes.byteLength !== stat.size) fail(`${label} changed while it was read`)
    return bytes
  } catch (error) {
    if (error instanceof StorageGenerationReceiptError) throw error
    fail(`${label} is unavailable: ${error?.code || error?.message || String(error)}`,
      'CORESTORE_GENERATION_RECEIPT_UNAVAILABLE')
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

// The pin is an external trust anchor only while this process cannot replace
// it. Check the effective runtime permission, rather than trusting a package
// manifest's mount declaration: an appliance may accidentally mount /config
// read-write even when its metadata says otherwise.
function assertRuntimeReadOnly (file, label) {
  let writable
  try {
    writable = openSync(file, FS_CONSTANTS.O_WRONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
  } catch (error) {
    if (error && ['EACCES', 'EPERM', 'EROFS'].includes(error.code)) return
    fail(`${label} cannot prove runtime read-only access: ${error?.code || error?.message || String(error)}`,
      'CORESTORE_GENERATION_RECEIPT_NOT_READ_ONLY')
  } finally {
    if (writable != null) closeSync(writable)
  }
  fail(`${label} must be read-only to the runtime`, 'CORESTORE_GENERATION_RECEIPT_NOT_READ_ONLY')
}

function assertOutsideStorage (file, storageRoot, label) {
  if (storageRoot == null) return
  if (typeof storageRoot !== 'string' || storageRoot.includes('\0')) throw new TypeError('generation storage root is invalid')
  const root = resolve(storageRoot)
  const rel = relative(root, file)
  if (rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))) {
    fail(`${label} must be external to the mutable Corestore generation root`,
      'CORESTORE_GENERATION_RECEIPT_NOT_EXTERNAL')
  }
}

function canonicalAbsolute (value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !isAbsolute(value) || normalize(value) !== value) {
    throw new TypeError(`${label} must be a canonical absolute path`)
  }
  return value
}

function canonicalBytes (value) {
  return Buffer.from(JSON.stringify(stableValue(value)) + '\n', 'utf8')
}

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort(compareCodeUnits).map(key => [key, stableValue(value[key])]))
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

function exactDigest (value, label) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${label} must be sha256:<64 lowercase hex>`)
  return value
}

function sha256 (bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function sameStrings (left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function compareCodeUnits (left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function fail (message, code) {
  throw new StorageGenerationReceiptError(message, code)
}
