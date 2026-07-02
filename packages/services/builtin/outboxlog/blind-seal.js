import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG,
  OUTBOXLOG_BLIND_SEAL_VERSION,
  createOutboxBlindSealedBody,
  isOutboxBlindSealedBody,
  verifyOutboxRecordSignature
} from './outbox-log.js'

export const OUTBOXLOG_BLIND_SEAL_KEY_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
export const OUTBOXLOG_BLIND_SEAL_NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
export const OUTBOXLOG_BLIND_SEAL_TAG_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
export const OUTBOXLOG_BLIND_SEAL_AAD_VERSION = 1
export const OUTBOXLOG_BLIND_SEAL_AAD_DOMAIN = 'outboxlog.blind.payload'
export const OUTBOXLOG_BLIND_KEY_ENVELOPE_VERSION = 1
export const OUTBOXLOG_BLIND_KEY_ENVELOPE_ALG = 'crypto_box_seal'
export const OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_VERSION = 1
export const OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_DOMAIN = 'outboxlog.blind.recipient'
export const OUTBOXLOG_BLIND_RECIPIENT_PUBLIC_KEY_BYTES = sodium.crypto_box_PUBLICKEYBYTES
export const OUTBOXLOG_BLIND_RECIPIENT_SECRET_KEY_BYTES = sodium.crypto_box_SECRETKEYBYTES
export const OUTBOXLOG_BLIND_KEY_ENVELOPE_SEAL_BYTES = sodium.crypto_box_SEALBYTES

export function createOutboxBlindSealKey () {
  const key = b4a.alloc(OUTBOXLOG_BLIND_SEAL_KEY_BYTES)
  sodium.randombytes_buf(key)
  return key
}

export function createOutboxBlindRecipientKeyPair ({ seed = null } = {}) {
  const publicKey = b4a.alloc(OUTBOXLOG_BLIND_RECIPIENT_PUBLIC_KEY_BYTES)
  const secretKey = b4a.alloc(OUTBOXLOG_BLIND_RECIPIENT_SECRET_KEY_BYTES)
  if (seed == null) sodium.crypto_box_keypair(publicKey, secretKey)
  else sodium.crypto_box_seed_keypair(publicKey, secretKey, normalizeSeed(seed))
  return {
    publicKey,
    secretKey,
    publicKeyHex: encodeOutboxBlindRecipientPublicKey(publicKey),
    secretKeyHex: encodeOutboxBlindRecipientSecretKey(secretKey)
  }
}

export function createOutboxBlindSealAAD ({
  namespace,
  appId,
  type,
  id,
  keyId = null,
  version = OUTBOXLOG_BLIND_SEAL_AAD_VERSION,
  domain = OUTBOXLOG_BLIND_SEAL_AAD_DOMAIN
} = {}) {
  if (version !== OUTBOXLOG_BLIND_SEAL_AAD_VERSION) throw new Error('OutboxLogBlindSeal: unsupported aad version')
  if (domain !== OUTBOXLOG_BLIND_SEAL_AAD_DOMAIN) throw new Error('OutboxLogBlindSeal: unsupported aad domain')
  return JSON.stringify({
    domain,
    version,
    namespace: normalizeAadField(namespace, 'namespace', 64),
    appId: normalizeAadField(appId, 'appId', 128),
    type: normalizeAadField(type, 'type', 64),
    id: normalizeAadField(id, 'id', 256),
    keyId: keyId == null ? null : normalizeAadField(keyId, 'keyId', 256)
  })
}

export function sealOutboxBlindPayload (payload, {
  key,
  nonce = null,
  aad = null,
  keyId = null,
  alg = OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG
} = {}) {
  if (alg !== OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG) throw new Error('OutboxLogBlindSeal: unsupported algorithm')
  const keyBuf = normalizeBlindSealKey(key)
  const nonceBuf = nonce == null ? randomNonce() : normalizeBlindSealNonce(nonce)
  const plaintext = encodePayload(payload)
  const additionalData = normalizeAad(aad)
  const ciphertext = b4a.alloc(plaintext.byteLength + OUTBOXLOG_BLIND_SEAL_TAG_BYTES)

  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    plaintext,
    additionalData,
    null,
    nonceBuf,
    keyBuf
  )

  return createOutboxBlindSealedBody({
    alg,
    nonce: encodeBase64Url(nonceBuf),
    ciphertext: encodeBase64Url(ciphertext),
    keyId
  })
}

export function openOutboxBlindPayload (body, { key, aad = null } = {}) {
  if (!isOutboxBlindSealedBody(body)) throw new Error('OutboxLogBlindSeal: invalid sealed body')
  const sealed = body.sealed
  if (sealed.version !== OUTBOXLOG_BLIND_SEAL_VERSION) throw new Error('OutboxLogBlindSeal: unsupported sealed body version')
  if (sealed.alg !== OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG) throw new Error('OutboxLogBlindSeal: unsupported algorithm')

  const keyBuf = normalizeBlindSealKey(key)
  const nonce = decodeBase64Url(sealed.nonce, 'nonce')
  const ciphertext = decodeBase64Url(sealed.ciphertext, 'ciphertext')
  if (nonce.byteLength !== OUTBOXLOG_BLIND_SEAL_NONCE_BYTES) throw new Error('OutboxLogBlindSeal: bad nonce')
  if (ciphertext.byteLength < OUTBOXLOG_BLIND_SEAL_TAG_BYTES) throw new Error('OutboxLogBlindSeal: bad ciphertext')

  const plaintext = b4a.alloc(ciphertext.byteLength - OUTBOXLOG_BLIND_SEAL_TAG_BYTES)
  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,
      null,
      ciphertext,
      normalizeAad(aad),
      nonce,
      keyBuf
    )
  } catch {
    throw new Error('OutboxLogBlindSeal: decrypt failed')
  }

  return decodePayload(plaintext)
}

export function wrapOutboxBlindSealKey (key, recipients, {
  version = OUTBOXLOG_BLIND_KEY_ENVELOPE_VERSION,
  alg = OUTBOXLOG_BLIND_KEY_ENVELOPE_ALG
} = {}) {
  if (version !== OUTBOXLOG_BLIND_KEY_ENVELOPE_VERSION) throw new Error('OutboxLogBlindSeal: unsupported key envelope version')
  if (alg !== OUTBOXLOG_BLIND_KEY_ENVELOPE_ALG) throw new Error('OutboxLogBlindSeal: unsupported key envelope algorithm')
  const keyBuf = normalizeBlindSealKey(key)
  const list = normalizeRecipients(recipients)
  if (list.length === 0) throw new Error('OutboxLogBlindSeal: at least one recipient required')

  return {
    version,
    alg,
    recipients: list.map((recipient) => {
      const sealedKey = b4a.alloc(keyBuf.byteLength + OUTBOXLOG_BLIND_KEY_ENVELOPE_SEAL_BYTES)
      sodium.crypto_box_seal(sealedKey, keyBuf, recipient.publicKey)
      return {
        id: recipient.id,
        publicKey: encodeOutboxBlindRecipientPublicKey(recipient.publicKey),
        sealedKey: encodeBase64Url(sealedKey)
      }
    })
  }
}

export function openOutboxBlindSealKeyEnvelope (envelope, {
  publicKey,
  secretKey,
  recipientId = null
} = {}) {
  const publicKeyBuf = normalizeRecipientPublicKey(publicKey)
  const secretKeyBuf = normalizeRecipientSecretKey(secretKey)
  const entry = selectRecipientEnvelope(envelope, publicKeyBuf, recipientId)
  const sealedKey = decodeBase64Url(entry.sealedKey, 'sealedKey')
  if (sealedKey.byteLength !== OUTBOXLOG_BLIND_SEAL_KEY_BYTES + OUTBOXLOG_BLIND_KEY_ENVELOPE_SEAL_BYTES) {
    throw new Error('OutboxLogBlindSeal: bad sealed key')
  }

  const key = b4a.alloc(OUTBOXLOG_BLIND_SEAL_KEY_BYTES)
  let opened = false
  try {
    opened = sodium.crypto_box_seal_open(key, sealedKey, publicKeyBuf, secretKeyBuf)
  } catch {
    throw new Error('OutboxLogBlindSeal: key unwrap failed')
  }
  if (opened === false) throw new Error('OutboxLogBlindSeal: key unwrap failed')
  return key
}

export function createOutboxBlindRecipientDirectoryEntry ({
  id,
  publicKey,
  namespace,
  appId = null,
  keyId,
  replacesKeyId = null,
  version = OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_VERSION,
  domain = OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_DOMAIN
} = {}) {
  if (version !== OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_VERSION) throw new Error('OutboxLogBlindSeal: unsupported recipient directory version')
  if (domain !== OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_DOMAIN) throw new Error('OutboxLogBlindSeal: unsupported recipient directory domain')
  const entry = {
    domain,
    version,
    namespace: normalizeDirectoryField(namespace, 'namespace', 64),
    appId: appId == null ? null : normalizeDirectoryField(appId, 'appId', 128),
    id: normalizeDirectoryField(id, 'id', 256),
    keyId: normalizeDirectoryField(keyId, 'keyId', 256),
    replacesKeyId: replacesKeyId == null ? null : normalizeDirectoryField(replacesKeyId, 'replacesKeyId', 256),
    publicKey: encodeOutboxBlindRecipientPublicKey(publicKey)
  }
  return {
    ...entry,
    fingerprint: fingerprintRecipientDirectoryEntry(entry)
  }
}

export function verifyOutboxBlindRecipientDirectoryEntry (entry, {
  namespace = null,
  appId = null,
  id = null,
  keyId = null,
  publicKey = null
} = {}) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('OutboxLogBlindSeal: invalid recipient directory entry')
  }
  const normalized = createOutboxBlindRecipientDirectoryEntry(entry)
  if (entry.fingerprint !== normalized.fingerprint) throw new Error('OutboxLogBlindSeal: recipient directory fingerprint mismatch')
  if (namespace != null && normalized.namespace !== String(namespace)) throw new Error('OutboxLogBlindSeal: recipient directory namespace mismatch')
  if (appId != null && normalized.appId !== String(appId)) throw new Error('OutboxLogBlindSeal: recipient directory appId mismatch')
  if (id != null && normalized.id !== String(id)) throw new Error('OutboxLogBlindSeal: recipient directory id mismatch')
  if (keyId != null && normalized.keyId !== String(keyId)) throw new Error('OutboxLogBlindSeal: recipient directory keyId mismatch')
  if (publicKey != null && normalized.publicKey !== encodeOutboxBlindRecipientPublicKey(publicKey)) {
    throw new Error('OutboxLogBlindSeal: recipient directory public key mismatch')
  }
  return normalized
}

export function verifyOutboxBlindRecipientDirectoryRotation (nextEntry, previousEntry, opts = {}) {
  const previous = verifyOutboxBlindRecipientDirectoryEntry(previousEntry, opts)
  const next = verifyOutboxBlindRecipientDirectoryEntry(nextEntry, opts)
  if (next.namespace !== previous.namespace) throw new Error('OutboxLogBlindSeal: recipient directory rotation namespace mismatch')
  if (next.appId !== previous.appId) throw new Error('OutboxLogBlindSeal: recipient directory rotation appId mismatch')
  if (next.id !== previous.id) throw new Error('OutboxLogBlindSeal: recipient directory rotation id mismatch')
  if (next.replacesKeyId !== previous.keyId) throw new Error('OutboxLogBlindSeal: recipient directory rotation replacesKeyId mismatch')
  if (next.keyId === previous.keyId) throw new Error('OutboxLogBlindSeal: recipient directory rotation keyId unchanged')
  if (next.publicKey === previous.publicKey) throw new Error('OutboxLogBlindSeal: recipient directory rotation public key unchanged')
  return next
}

export function verifyOutboxBlindRecipientDirectoryRecord (record, {
  trustedPublishers,
  publisherId = null,
  type = 'recipient',
  namespace = null,
  namespaces = null,
  recipientField = 'recipient',
  directoryEntry = null,
  entryOpts = {}
} = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('OutboxLogBlindSeal: invalid recipient directory record')
  }

  const publisher = normalizePublisherPublicKey(publisherId || record._k || record.author, 'recipient directory publisher')
  const trusted = normalizeTrustedPublishers(trustedPublishers)
  if (!trusted.has(publisher)) throw new Error('OutboxLogBlindSeal: untrusted recipient directory publisher')
  if (record._k != null && normalizePublisherPublicKey(record._k, 'recipient directory record _k') !== publisher) {
    throw new Error('OutboxLogBlindSeal: recipient directory publisher mismatch')
  }
  if (record.author != null && normalizePublisherPublicKey(record.author, 'recipient directory record author') !== publisher) {
    throw new Error('OutboxLogBlindSeal: recipient directory publisher mismatch')
  }

  const expectedNamespace = namespace == null ? null : String(namespace)
  if (expectedNamespace != null && record._ns !== expectedNamespace) {
    throw new Error('OutboxLogBlindSeal: recipient directory record namespace mismatch')
  }
  const verifierNamespace = expectedNamespace || (typeof record._ns === 'string' ? record._ns : undefined)
  if (!verifyOutboxRecordSignature({
    appId: publisher,
    type,
    data: record
  }, {
    namespace: verifierNamespace,
    namespaces
  })) {
    throw new Error('OutboxLogBlindSeal: recipient directory record signature mismatch')
  }

  const entry = directoryEntry == null ? record[recipientField] : directoryEntry
  return {
    publisherId: publisher,
    recipient: verifyOutboxBlindRecipientDirectoryEntry(entry, entryOpts)
  }
}

export function encodeOutboxBlindSealKey (key) {
  return b4a.toString(normalizeBlindSealKey(key), 'hex')
}

export function decodeOutboxBlindSealKey (key) {
  return normalizeBlindSealKey(key)
}

export function encodeOutboxBlindRecipientPublicKey (publicKey) {
  return b4a.toString(normalizeRecipientPublicKey(publicKey), 'hex')
}

export function decodeOutboxBlindRecipientPublicKey (publicKey) {
  return normalizeRecipientPublicKey(publicKey)
}

export function encodeOutboxBlindRecipientSecretKey (secretKey) {
  return b4a.toString(normalizeRecipientSecretKey(secretKey), 'hex')
}

export function decodeOutboxBlindRecipientSecretKey (secretKey) {
  return normalizeRecipientSecretKey(secretKey)
}

function randomNonce () {
  const nonce = b4a.alloc(OUTBOXLOG_BLIND_SEAL_NONCE_BYTES)
  sodium.randombytes_buf(nonce)
  return nonce
}

function normalizeBlindSealKey (key) {
  if (typeof key === 'string') {
    if (!/^[0-9a-f]{64}$/i.test(key)) throw new Error('OutboxLogBlindSeal: key must be 32 bytes')
    key = b4a.from(key, 'hex')
  } else if (key && typeof key.byteLength === 'number') {
    key = b4a.from(key)
  }
  if (!b4a.isBuffer(key) || key.byteLength !== OUTBOXLOG_BLIND_SEAL_KEY_BYTES) {
    throw new Error('OutboxLogBlindSeal: key must be 32 bytes')
  }
  return key
}

function normalizeRecipientPublicKey (publicKey) {
  return normalizeHexOrBuffer(publicKey, OUTBOXLOG_BLIND_RECIPIENT_PUBLIC_KEY_BYTES, 'recipient public key')
}

function normalizeRecipientSecretKey (secretKey) {
  return normalizeHexOrBuffer(secretKey, OUTBOXLOG_BLIND_RECIPIENT_SECRET_KEY_BYTES, 'recipient secret key')
}

function normalizeSeed (seed) {
  return normalizeHexOrBuffer(seed, sodium.crypto_box_SEEDBYTES || OUTBOXLOG_BLIND_RECIPIENT_SECRET_KEY_BYTES, 'recipient seed')
}

function normalizeHexOrBuffer (value, bytes, label) {
  if (typeof value === 'string') {
    if (!new RegExp('^[0-9a-f]{' + (bytes * 2) + '}$', 'i').test(value)) {
      throw new Error('OutboxLogBlindSeal: ' + label + ' must be ' + bytes + ' bytes')
    }
    value = b4a.from(value, 'hex')
  } else if (value && typeof value.byteLength === 'number') {
    value = b4a.from(value)
  }
  if (!b4a.isBuffer(value) || value.byteLength !== bytes) {
    throw new Error('OutboxLogBlindSeal: ' + label + ' must be ' + bytes + ' bytes')
  }
  return value
}

function normalizeRecipients (recipients) {
  const input = Array.isArray(recipients) ? recipients : [recipients]
  return input
    .filter(Boolean)
    .map((recipient) => {
      if (typeof recipient === 'string' || (recipient && typeof recipient.byteLength === 'number')) {
        const publicKey = normalizeRecipientPublicKey(recipient)
        return {
          id: encodeOutboxBlindRecipientPublicKey(publicKey),
          publicKey
        }
      }
      if (!recipient || typeof recipient !== 'object' || Array.isArray(recipient)) {
        throw new Error('OutboxLogBlindSeal: bad recipient')
      }
      const publicKey = normalizeRecipientPublicKey(recipient.publicKey || recipient.publicKeyHex)
      const id = recipient.id == null ? encodeOutboxBlindRecipientPublicKey(publicKey) : String(recipient.id)
      if (!id || id.length > 256) throw new Error('OutboxLogBlindSeal: bad recipient id')
      return { id, publicKey }
    })
}

function selectRecipientEnvelope (envelope, publicKey, recipientId) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('OutboxLogBlindSeal: invalid key envelope')
  }
  if (envelope.version !== OUTBOXLOG_BLIND_KEY_ENVELOPE_VERSION) throw new Error('OutboxLogBlindSeal: unsupported key envelope version')
  if (envelope.alg !== OUTBOXLOG_BLIND_KEY_ENVELOPE_ALG) throw new Error('OutboxLogBlindSeal: unsupported key envelope algorithm')
  if (!Array.isArray(envelope.recipients)) throw new Error('OutboxLogBlindSeal: invalid key envelope recipients')
  const publicKeyHex = encodeOutboxBlindRecipientPublicKey(publicKey)
  const entry = envelope.recipients.find((recipient) => {
    if (!recipient || typeof recipient !== 'object' || Array.isArray(recipient)) return false
    if (recipientId != null) return recipient.id === recipientId
    return recipient.publicKey === publicKeyHex
  })
  if (!entry) throw new Error('OutboxLogBlindSeal: recipient not found')
  if (entry.publicKey !== publicKeyHex) throw new Error('OutboxLogBlindSeal: recipient public key mismatch')
  if (typeof entry.sealedKey !== 'string') throw new Error('OutboxLogBlindSeal: bad sealed key')
  return entry
}

function normalizeBlindSealNonce (nonce) {
  if (typeof nonce === 'string') nonce = decodeBase64Url(nonce, 'nonce')
  else if (nonce && typeof nonce.byteLength === 'number') nonce = b4a.from(nonce)
  if (!b4a.isBuffer(nonce) || nonce.byteLength !== OUTBOXLOG_BLIND_SEAL_NONCE_BYTES) {
    throw new Error('OutboxLogBlindSeal: nonce must be 24 bytes')
  }
  return nonce
}

function normalizeAad (aad) {
  if (aad == null) return null
  if (typeof aad === 'string') return b4a.from(aad, 'utf8')
  if (aad && typeof aad.byteLength === 'number') return b4a.from(aad)
  throw new Error('OutboxLogBlindSeal: aad must be a string or buffer')
}

function normalizeAadField (value, label, maxLength) {
  if (value == null) throw new Error('OutboxLogBlindSeal: aad ' + label + ' required')
  value = String(value)
  if (!value || value.length > maxLength) throw new Error('OutboxLogBlindSeal: bad aad ' + label)
  return value
}

function normalizeDirectoryField (value, label, maxLength) {
  if (value == null) throw new Error('OutboxLogBlindSeal: recipient directory ' + label + ' required')
  value = String(value)
  if (!value || value.length > maxLength) throw new Error('OutboxLogBlindSeal: bad recipient directory ' + label)
  return value
}

function normalizePublisherPublicKey (value, label) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    value = value.publicKey || value.publicKeyHex || value.id
  }
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error('OutboxLogBlindSeal: ' + label + ' must be 32-byte public key')
    return value.toLowerCase()
  }
  if (value && typeof value.byteLength === 'number') {
    const buffer = b4a.from(value)
    if (buffer.byteLength !== 32) throw new Error('OutboxLogBlindSeal: ' + label + ' must be 32-byte public key')
    return b4a.toString(buffer, 'hex')
  }
  throw new Error('OutboxLogBlindSeal: ' + label + ' must be 32-byte public key')
}

function normalizeTrustedPublishers (trustedPublishers) {
  const input = trustedPublishers instanceof Set
    ? [...trustedPublishers]
    : (Array.isArray(trustedPublishers) ? trustedPublishers : null)
  if (!input || input.length === 0) throw new Error('OutboxLogBlindSeal: recipient directory trusted publishers required')
  return new Set(input.map((publisher) => normalizePublisherPublicKey(publisher, 'trusted recipient directory publisher')))
}

function fingerprintRecipientDirectoryEntry (entry) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(JSON.stringify(entry), 'utf8'))
  return b4a.toString(out, 'hex')
}

function encodePayload (payload) {
  let text
  try {
    text = JSON.stringify(payload)
  } catch {
    throw new Error('OutboxLogBlindSeal: payload must be JSON serializable')
  }
  if (typeof text !== 'string') throw new Error('OutboxLogBlindSeal: payload must be JSON serializable')
  return b4a.from(text, 'utf8')
}

function decodePayload (plaintext) {
  try {
    return JSON.parse(b4a.toString(plaintext, 'utf8'))
  } catch {
    throw new Error('OutboxLogBlindSeal: payload decode failed')
  }
}

function encodeBase64Url (buffer) {
  return Buffer.from(buffer).toString('base64url')
}

function decodeBase64Url (value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new Error('OutboxLogBlindSeal: bad ' + label)
  try {
    return b4a.from(Buffer.from(value, 'base64url'))
  } catch {
    throw new Error('OutboxLogBlindSeal: bad ' + label)
  }
}
