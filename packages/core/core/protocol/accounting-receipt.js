/**
 * Accounting Receipt Protocol
 *
 * RelayKernel and HiveMesh both call for signed, OS-grounded accounting
 * receipts. This helper is deliberately pure and additive: current HiveRelay
 * runtime behavior is unchanged, but tests and future integration work can
 * exercise a receipt shape that binds the relay identity to measured disk
 * usage and content-free bandwidth counters.
 */
import b4a from 'b4a'
import sodium from 'sodium-universal'

export const ACCOUNTING_RECEIPT_KIND = 'hiverelay-accounting-receipt'
export const ACCOUNTING_RECEIPT_DOMAIN = 'hiverelay.accounting.receipt.v1'
export const ACCOUNTING_RECEIPT_VERSION = 1
export const ACCOUNTING_RECEIPT_SOURCE = 'storage-accounting-summary-v1'

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_16 = /^[0-9a-f]{32}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i

const ALLOWED_FIELDS = new Set([
  'kind',
  'version',
  'relayPubkey',
  'periodStart',
  'periodEnd',
  'measuredAt',
  'storageBytes',
  'diskBytes',
  'perEntryBytes',
  'bytesServed',
  'bytesReceived',
  'leaseCount',
  'seededCount',
  'source',
  'nonce',
  'signature'
])

export function accountingFieldsFromStorageSummary (summary, opts = {}) {
  if (!summary || typeof summary !== 'object') {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: storage summary required')
  }
  if (!Number.isSafeInteger(summary.diskBytes) || summary.diskBytes < 0) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: diskBytes required for OS-grounded receipt')
  }

  const measuredAt = safeInteger(opts.measuredAt, Date.now(), 'measuredAt')
  return {
    periodStart: safeInteger(opts.periodStart, measuredAt, 'periodStart'),
    periodEnd: safeInteger(opts.periodEnd, measuredAt, 'periodEnd'),
    measuredAt,
    storageBytes: safeInteger(summary.totalBytes, summary.diskBytes, 'storageBytes'),
    diskBytes: summary.diskBytes,
    perEntryBytes: safeInteger(summary.perEntryBytes, 0, 'perEntryBytes'),
    bytesServed: safeInteger(opts.bytesServed, 0, 'bytesServed'),
    bytesReceived: safeInteger(opts.bytesReceived, 0, 'bytesReceived'),
    leaseCount: safeInteger(opts.leaseCount, 0, 'leaseCount'),
    seededCount: safeInteger(opts.seededCount, summary.measuredEntries || 0, 'seededCount'),
    source: ACCOUNTING_RECEIPT_SOURCE
  }
}

export function createAccountingReceipt (keyPair, fields = {}) {
  requireKeyPair(keyPair, 'keyPair')
  if (fields.signature != null) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: signature is derived')
  }

  const nonce = fields.nonce || randomNonceHex()
  const relayPubkey = b4a.toString(keyPair.publicKey, 'hex')
  const raw = {
    kind: ACCOUNTING_RECEIPT_KIND,
    version: ACCOUNTING_RECEIPT_VERSION,
    periodStart: 0,
    periodEnd: 0,
    measuredAt: Date.now(),
    storageBytes: 0,
    diskBytes: 0,
    perEntryBytes: 0,
    bytesServed: 0,
    bytesReceived: 0,
    leaseCount: 0,
    seededCount: 0,
    source: ACCOUNTING_RECEIPT_SOURCE,
    ...fields,
    relayPubkey,
    nonce
  }

  const receipt = normalizeAccountingReceipt(raw, { signatureRequired: false })
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, accountingReceiptSignable(receipt), keyPair.secretKey)
  return {
    ...receipt,
    signature: b4a.toString(signature, 'hex')
  }
}

export function verifyAccountingReceipt (receipt) {
  try {
    const normalized = normalizeAccountingReceipt(receipt, { signatureRequired: true })
    const ok = sodium.crypto_sign_verify_detached(
      b4a.from(normalized.signature, 'hex'),
      accountingReceiptSignable(normalized),
      b4a.from(normalized.relayPubkey, 'hex')
    )
    if (!ok) return { valid: false, reason: 'bad signature' }
    return { valid: true, receipt: normalized }
  } catch (err) {
    return { valid: false, reason: err.message || String(err) }
  }
}

export function accountingReceiptSignable (receipt) {
  const r = normalizeAccountingReceipt(receipt, { signatureRequired: false })
  return b4a.from(JSON.stringify([
    ACCOUNTING_RECEIPT_DOMAIN,
    r.kind,
    r.version,
    r.relayPubkey,
    r.periodStart,
    r.periodEnd,
    r.measuredAt,
    r.storageBytes,
    r.diskBytes,
    r.perEntryBytes,
    r.bytesServed,
    r.bytesReceived,
    r.leaseCount,
    r.seededCount,
    r.source,
    r.nonce
  ]), 'utf8')
}

export function normalizeAccountingReceipt (receipt, opts = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: receipt object required')
  }

  for (const key of Object.keys(receipt)) {
    if (!ALLOWED_FIELDS.has(key)) throw new Error('ACCOUNTING_RECEIPT_INVALID: unknown field ' + key)
  }

  const out = {
    kind: String(receipt.kind || ''),
    version: integerField(receipt.version, 'version'),
    relayPubkey: lowerHex(receipt.relayPubkey, HEX_32, 'relayPubkey'),
    periodStart: integerField(receipt.periodStart, 'periodStart'),
    periodEnd: integerField(receipt.periodEnd, 'periodEnd'),
    measuredAt: integerField(receipt.measuredAt, 'measuredAt'),
    storageBytes: integerField(receipt.storageBytes, 'storageBytes'),
    diskBytes: integerField(receipt.diskBytes, 'diskBytes'),
    perEntryBytes: integerField(receipt.perEntryBytes, 'perEntryBytes'),
    bytesServed: integerField(receipt.bytesServed, 'bytesServed'),
    bytesReceived: integerField(receipt.bytesReceived, 'bytesReceived'),
    leaseCount: integerField(receipt.leaseCount, 'leaseCount'),
    seededCount: integerField(receipt.seededCount, 'seededCount'),
    source: String(receipt.source || ''),
    nonce: lowerHex(receipt.nonce, HEX_16, 'nonce')
  }

  if (out.kind !== ACCOUNTING_RECEIPT_KIND) throw new Error('ACCOUNTING_RECEIPT_INVALID: kind mismatch')
  if (out.version !== ACCOUNTING_RECEIPT_VERSION) throw new Error('ACCOUNTING_RECEIPT_INVALID: version mismatch')
  if (out.source !== ACCOUNTING_RECEIPT_SOURCE) throw new Error('ACCOUNTING_RECEIPT_INVALID: source mismatch')
  if (out.periodEnd < out.periodStart) throw new Error('ACCOUNTING_RECEIPT_INVALID: periodEnd before periodStart')
  if (out.measuredAt < out.periodStart) throw new Error('ACCOUNTING_RECEIPT_INVALID: measuredAt before periodStart')
  if (out.storageBytes < out.diskBytes) throw new Error('ACCOUNTING_RECEIPT_INVALID: storageBytes below diskBytes')
  if (out.storageBytes < out.perEntryBytes) throw new Error('ACCOUNTING_RECEIPT_INVALID: storageBytes below perEntryBytes')

  if (receipt.signature != null) {
    out.signature = lowerHex(receipt.signature, HEX_SIG, 'signature')
  } else if (opts.signatureRequired) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: signature required')
  }

  return out
}

function requireKeyPair (keyPair, name) {
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: ' + name + ' required')
  }
  if (keyPair.publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: bad public key')
  }
  if (keyPair.secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: bad secret key')
  }
}

function randomNonceHex () {
  const nonce = b4a.alloc(16)
  sodium.randombytes_buf(nonce)
  return b4a.toString(nonce, 'hex')
}

function lowerHex (value, re, name) {
  const out = String(value || '').toLowerCase()
  if (!re.test(out)) throw new Error('ACCOUNTING_RECEIPT_INVALID: bad ' + name)
  return out
}

function integerField (value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: bad ' + name)
  }
  return value
}

function safeInteger (value, fallback, name) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: bad ' + name)
  }
  return value
}
