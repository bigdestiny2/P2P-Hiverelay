import b4a from 'b4a'
import sodium from 'sodium-universal'

export const APP_RELEASE_PROTOCOL_VERSION = 1
export const APP_RELEASE_SIGNATURE_DOMAIN = 'hiverelay.app-release.v1'
export const MAX_RELEASE_ROLLBACK_WINDOW = 32

const RELEASE_FIELDS = new Set([
  'protocolVersion',
  'appId',
  'version',
  'sequence',
  'generation',
  'driveKey',
  'previousDriveKey',
  'rotationReason',
  'storageBudgetBytes',
  'rollbackWindow',
  'rollbackDriveKeys',
  'treeHash',
  'issuedAt',
  'publisherPubkey',
  'signature'
])

function hexKey (value, bytes) {
  return typeof value === 'string' && value.length === bytes * 2 && /^[0-9a-f]+$/i.test(value)
    ? value.toLowerCase()
    : null
}

function safeText (value, maxBytes) {
  if (typeof value !== 'string' || value.length === 0) return null
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return null
  }
  return b4a.byteLength(value) <= maxBytes ? value : null
}

function normalizeRelease (input, opts = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('release must be an object')
  for (const field of Object.keys(input)) {
    if (!RELEASE_FIELDS.has(field)) throw new Error(`unknown release field: ${field}`)
  }

  if (input.protocolVersion !== APP_RELEASE_PROTOCOL_VERSION) throw new Error('unsupported release protocolVersion')
  const appId = safeText(input.appId, 128)
  if (!appId) throw new Error('release appId must be 1-128 safe UTF-8 bytes')
  const version = safeText(input.version, 64)
  if (!version) throw new Error('release version must be 1-64 safe UTF-8 bytes')
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) throw new Error('release sequence must be a positive safe integer')
  if (!Number.isSafeInteger(input.generation) || input.generation < 1) throw new Error('release generation must be a positive safe integer')

  const driveKey = hexKey(input.driveKey, 32)
  if (!driveKey) throw new Error('release driveKey must be 64 hex characters')
  const previousDriveKey = input.previousDriveKey === null ? null : hexKey(input.previousDriveKey, 32)
  if (input.previousDriveKey !== null && !previousDriveKey) throw new Error('release previousDriveKey must be null or 64 hex characters')
  if (previousDriveKey === driveKey) throw new Error('release previousDriveKey must differ from driveKey')

  const rotationReason = input.rotationReason === null ? null : input.rotationReason
  if (previousDriveKey && rotationReason !== 'storage-budget') {
    throw new Error('release-key rotation must declare storage-budget')
  }
  if (!previousDriveKey && rotationReason !== null) {
    throw new Error('rotationReason requires previousDriveKey')
  }

  if (!Number.isSafeInteger(input.storageBudgetBytes) || input.storageBudgetBytes < 1) {
    throw new Error('release storageBudgetBytes must be a positive safe integer')
  }
  if (!Number.isSafeInteger(input.rollbackWindow) || input.rollbackWindow < 1 || input.rollbackWindow > MAX_RELEASE_ROLLBACK_WINDOW) {
    throw new Error(`release rollbackWindow must be in [1,${MAX_RELEASE_ROLLBACK_WINDOW}]`)
  }
  if (!Array.isArray(input.rollbackDriveKeys) || input.rollbackDriveKeys.length > input.rollbackWindow - 1) {
    throw new Error('release rollbackDriveKeys exceeds rollbackWindow')
  }
  const rollbackDriveKeys = []
  const seen = new Set([driveKey])
  for (const value of input.rollbackDriveKeys) {
    const key = hexKey(value, 32)
    if (!key) throw new Error('release rollbackDriveKeys must contain 64-hex keys')
    if (seen.has(key)) throw new Error('release rollbackDriveKeys must be unique and exclude driveKey')
    seen.add(key)
    rollbackDriveKeys.push(key)
  }
  if (previousDriveKey && input.rollbackWindow > 1 && !seen.has(previousDriveKey)) {
    throw new Error('release rollback window must retain its predecessor')
  }

  const treeHash = hexKey(input.treeHash, 32)
  if (!treeHash) throw new Error('release treeHash must be 64 hex characters')
  if (!Number.isSafeInteger(input.issuedAt) || input.issuedAt < 0) throw new Error('release issuedAt must be a non-negative safe integer')
  const maxFutureSkewMs = Number.isSafeInteger(opts.maxFutureSkewMs) ? opts.maxFutureSkewMs : 60_000
  const now = Number.isSafeInteger(opts.now) ? opts.now : Date.now()
  if (opts.checkTime !== false && input.issuedAt > now + maxFutureSkewMs) throw new Error('release issuedAt is too far in the future')

  const publisherPubkey = hexKey(input.publisherPubkey, 32)
  if (!publisherPubkey) throw new Error('release publisherPubkey must be 64 hex characters')
  const signature = input.signature === undefined && opts.allowUnsigned
    ? null
    : hexKey(input.signature, 64)
  if (!signature && !opts.allowUnsigned) throw new Error('release signature must be 128 hex characters')

  return {
    protocolVersion: APP_RELEASE_PROTOCOL_VERSION,
    appId,
    version,
    sequence: input.sequence,
    generation: input.generation,
    driveKey,
    previousDriveKey,
    rotationReason,
    storageBudgetBytes: input.storageBudgetBytes,
    rollbackWindow: input.rollbackWindow,
    rollbackDriveKeys,
    treeHash,
    issuedAt: input.issuedAt,
    publisherPubkey,
    ...(signature ? { signature } : {})
  }
}

function signingFields (release) {
  return [
    release.protocolVersion,
    release.appId,
    release.version,
    release.sequence,
    release.generation,
    release.driveKey,
    release.previousDriveKey,
    release.rotationReason,
    release.storageBudgetBytes,
    release.rollbackWindow,
    release.rollbackDriveKeys,
    release.treeHash,
    release.issuedAt,
    release.publisherPubkey
  ]
}

export function serializeAppReleaseForSigning (input) {
  const release = normalizeRelease(input, { allowUnsigned: true, checkTime: false })
  return b4a.concat([
    b4a.from(APP_RELEASE_SIGNATURE_DOMAIN),
    b4a.from([0]),
    b4a.from(JSON.stringify(signingFields(release)))
  ])
}

export function signAppRelease (input, keyPair) {
  if (!keyPair || !b4a.isBuffer(keyPair.publicKey) || keyPair.publicKey.byteLength !== 32 ||
      !b4a.isBuffer(keyPair.secretKey) || keyPair.secretKey.byteLength !== 64) {
    throw new Error('release keyPair must contain an Ed25519 publicKey and secretKey')
  }
  const publisherPubkey = b4a.toString(keyPair.publicKey, 'hex')
  const release = normalizeRelease({ ...input, publisherPubkey }, { allowUnsigned: true, checkTime: false })
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, serializeAppReleaseForSigning(release), keyPair.secretKey)
  return { ...release, signature: b4a.toString(signature, 'hex') }
}

export function verifyAppRelease (input, opts = {}) {
  try {
    const release = normalizeRelease(input, opts)
    const valid = sodium.crypto_sign_verify_detached(
      b4a.from(release.signature, 'hex'),
      serializeAppReleaseForSigning(release),
      b4a.from(release.publisherPubkey, 'hex')
    )
    if (!valid) return { ok: false, error: 'release signature does not verify' }
    return { ok: true, release }
  } catch (err) {
    return { ok: false, error: err.message }
  }
}

function uint32 (value) {
  const out = b4a.alloc(4)
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(0, value)
  return out
}

function uint64 (value) {
  const out = b4a.alloc(8)
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(0, BigInt(value))
  return out
}

export function hashReleaseTree (files) {
  if (!Array.isArray(files)) throw new Error('release files must be an array')
  const normalized = files.map(file => {
    if (!file || typeof file.path !== 'string' || !file.path.startsWith('/') || file.path.includes('\\')) {
      throw new Error('release file paths must be absolute Hyperdrive paths')
    }
    return {
      path: file.path,
      content: b4a.isBuffer(file.content) ? file.content : b4a.from(file.content)
    }
  }).sort((a, b) => a.path.localeCompare(b.path))

  const seen = new Set()
  const parts = [b4a.from('hiverelay.app-release-tree.v1'), b4a.from([0])]
  for (const file of normalized) {
    if (seen.has(file.path)) throw new Error(`duplicate release path: ${file.path}`)
    seen.add(file.path)
    const path = b4a.from(file.path)
    const contentHash = b4a.alloc(32)
    sodium.crypto_generichash(contentHash, file.content)
    parts.push(uint32(path.byteLength), path, uint64(file.content.byteLength), contentHash)
  }
  const treeHash = b4a.alloc(32)
  sodium.crypto_generichash(treeHash, b4a.concat(parts))
  return b4a.toString(treeHash, 'hex')
}
