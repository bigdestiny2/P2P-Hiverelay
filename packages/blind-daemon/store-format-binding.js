import fs from 'node:fs/promises'
import b4a from 'b4a'
import { verifyStoreFormatAuthorityV1 } from '@hiverelay/blind-protocol'

const AUTHORITY_URL = new URL(
  '../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
  import.meta.url
)
const SCHEMA_CATALOG_URL = new URL(
  '../blind-protocol/hiverelay-blind-store-schema-catalog-v1.draft.cenc',
  import.meta.url
)
const ACTIVE_BINDINGS = new WeakSet()
const BINDING_STATE = new WeakMap()
const ZERO32 = b4a.alloc(32)

export const BLIND_STORE_FORMAT_AUTHORITY_STATUS = Object.freeze({
  authorityArtifact: 'hiverelay-blind-store-format-authority-v1.draft.cenc',
  schemaCatalogArtifact: 'hiverelay-blind-store-schema-catalog-v1.draft.cenc',
  executableArtifactVerifier: true,
  exactDescriptorHashBinding: true,
  exactRuntimeRootBinding: true,
  exactStorageEngineBinding: true,
  finalAuthorityPublished: false,
  blocker: 'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED'
})

export class BlindStoreFormatAuthorityError extends Error {
  constructor (message, cause = null) {
    super(message, cause == null ? undefined : { cause })
    this.name = 'BlindStoreFormatAuthorityError'
    this.code = 'BLIND_STORE_FORMAT_AUTHORITY_INVALID'
  }
}

function bytes32 (value, field) {
  if (!value || typeof value.byteLength !== 'number') {
    throw new BlindStoreFormatAuthorityError(`${field} must be exactly 32 bytes`)
  }
  const normalized = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (normalized.byteLength !== 32 || b4a.equals(normalized, ZERO32)) {
    throw new BlindStoreFormatAuthorityError(`${field} must be a nonzero 32-byte hash`)
  }
  return normalized
}

function formatComponent (value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new BlindStoreFormatAuthorityError(`${field} must be a u16 integer`)
  }
  return value
}

export function createBlindStoreFormatAuthorityBinding (options = {}) {
  const expectedStoreFormatHash = bytes32(options.expectedStoreFormatHash, 'expectedStoreFormatHash')
  const expectedFormatMajor = formatComponent(options.expectedFormatMajor, 'expectedFormatMajor')
  const expectedFormatMinor = formatComponent(options.expectedFormatMinor, 'expectedFormatMinor')
  let verified
  try {
    verified = verifyStoreFormatAuthorityV1(options.authorityBytes, {
      schemaCatalogBytes: options.schemaCatalogBytes,
      expectedStoreFormatHash
    })
  } catch (error) {
    throw new BlindStoreFormatAuthorityError(`store-format artifact verification failed: ${error.message}`, error)
  }
  if (verified.formatMajor !== expectedFormatMajor || verified.formatMinor !== expectedFormatMinor) {
    throw new BlindStoreFormatAuthorityError(
      `store-format artifact ${verified.formatMajor}.${verified.formatMinor} does not match expected ` +
      `${expectedFormatMajor}.${expectedFormatMinor}`
    )
  }

  const state = Object.freeze({
    authorityVersion: verified.authorityVersion,
    formatMajor: verified.formatMajor,
    formatMinor: verified.formatMinor,
    storeFormatHash: b4a.from(verified.storeFormatHash)
  })
  const binding = {}
  Object.defineProperties(binding, {
    authorityVersion: { enumerable: true, value: state.authorityVersion },
    formatMajor: { enumerable: true, value: state.formatMajor },
    formatMinor: { enumerable: true, value: state.formatMinor },
    storeFormatHash: { enumerable: true, get: () => b4a.from(state.storeFormatHash) },
    publicationFinal: { enumerable: true, value: false }
  })
  Object.freeze(binding)
  ACTIVE_BINDINGS.add(binding)
  BINDING_STATE.set(binding, state)
  return binding
}

export function inspectBlindStoreFormatAuthorityBinding (binding) {
  if (!binding || typeof binding !== 'object' || !ACTIVE_BINDINGS.has(binding)) {
    throw new BlindStoreFormatAuthorityError('store-format authority binding is forged or unsupported')
  }
  const state = BINDING_STATE.get(binding)
  if (!state || binding.authorityVersion !== state.authorityVersion ||
      binding.formatMajor !== state.formatMajor || binding.formatMinor !== state.formatMinor ||
      !b4a.equals(binding.storeFormatHash, state.storeFormatHash) || binding.publicationFinal !== false) {
    throw new BlindStoreFormatAuthorityError('store-format authority binding state is inconsistent')
  }
  return Object.freeze({
    authorityVersion: state.authorityVersion,
    formatMajor: state.formatMajor,
    formatMinor: state.formatMinor,
    storeFormatHash: b4a.from(state.storeFormatHash),
    publicationFinal: false
  })
}

export async function loadBundledBlindStoreFormatAuthority (options = {}) {
  const [authorityBytes, schemaCatalogBytes] = await Promise.all([
    fs.readFile(AUTHORITY_URL),
    fs.readFile(SCHEMA_CATALOG_URL)
  ])
  return createBlindStoreFormatAuthorityBinding({
    authorityBytes,
    schemaCatalogBytes,
    expectedStoreFormatHash: options.expectedStoreFormatHash,
    expectedFormatMajor: options.expectedFormatMajor,
    expectedFormatMinor: options.expectedFormatMinor
  })
}
