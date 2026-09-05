import b4a from 'b4a'
import sodium from 'sodium-universal'

export const ACCOUNTING_RECEIPT_KIND = 'hiverelay-accounting-receipt-v2'
export const ACCOUNTING_RECEIPT_DOMAIN = 'hiverelay.accounting.receipt.v2'
export const ACCOUNTING_RECEIPT_VERSION = 2
export const ACCOUNTING_RECEIPT_SOURCE = 'storage-accounting-complete-sample-v2'
export const ACCOUNTING_ALLOWED_INTERVAL_MS = 1_980_000
export const ACCOUNTING_COMPLETION_MAX_AGE_MS = 1_800_000
export const ACCOUNTING_OBSERVED_MAX_AGE_MS = 86_400_000
export const ACCOUNTING_EPOCH_MAX_DURATION_MS = 28_800_000

const LEGACY_KIND = 'hiverelay-accounting-receipt'
const LEGACY_DOMAIN = 'hiverelay.accounting.receipt.v1'
const LEGACY_VERSION = 1
const LEGACY_SOURCE = 'storage-accounting-summary-v1'

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_16 = /^[0-9a-f]{32}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i

const V2_FIELDS = new Set([
  'kind', 'version', 'relayPubkey', 'periodStart', 'periodEnd',
  'observedAt', 'completedAt', 'storageBytes', 'diskBytes',
  'perEntryBytes', 'bytesServed', 'bytesReceived', 'leaseCount',
  'seededCount', 'source', 'nonce', 'signature'
])

const V1_FIELDS = new Set([
  'kind', 'version', 'relayPubkey', 'periodStart', 'periodEnd',
  'measuredAt', 'storageBytes', 'diskBytes', 'perEntryBytes',
  'bytesServed', 'bytesReceived', 'leaseCount', 'seededCount',
  'source', 'nonce', 'signature'
])

export function accountingFieldsFromStorageSummary (summary, opts = {}) {
  if (!summary || typeof summary !== 'object') {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: storage summary required')
  }
  if (summary.diskMeasurementComplete !== true) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: complete storage sample required')
  }
  const diskBytes = integerField(summary.diskBytes, 'diskBytes')
  const observedAt = integerField(summary.diskObservedAt, 'observedAt')
  const completedAt = integerField(summary.diskCompletedAt, 'completedAt')
  if (completedAt < observedAt) throw new Error('ACCOUNTING_RECEIPT_INVALID: completedAt before observedAt')
  if (opts.observedAt != null || opts.completedAt != null || opts.measuredAt != null) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: sample timestamps are derived')
  }
  return {
    periodStart: safeInteger(opts.periodStart, observedAt, 'periodStart'),
    periodEnd: safeInteger(opts.periodEnd, completedAt, 'periodEnd'),
    observedAt,
    completedAt,
    storageBytes: safeInteger(summary.totalBytes, diskBytes, 'storageBytes'),
    diskBytes,
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
  if (fields.signature != null || fields.relayPubkey != null) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: signature and relayPubkey are derived')
  }
  const verifierNow = Date.now()
  const raw = {
    periodStart: 0,
    periodEnd: 0,
    observedAt: 0,
    completedAt: 0,
    storageBytes: 0,
    diskBytes: 0,
    perEntryBytes: 0,
    bytesServed: 0,
    bytesReceived: 0,
    leaseCount: 0,
    seededCount: 0,
    ...fields,
    kind: ACCOUNTING_RECEIPT_KIND,
    version: ACCOUNTING_RECEIPT_VERSION,
    source: ACCOUNTING_RECEIPT_SOURCE,
    relayPubkey: b4a.toString(keyPair.publicKey, 'hex'),
    nonce: fields.nonce || randomNonceHex()
  }
  const receipt = normalizeAccountingReceipt(raw, { signatureRequired: false })
  const evidence = accountingReceiptEvidence(receipt, verifierNow)
  if (!evidence.eligible) throw new Error('ACCOUNTING_RECEIPT_INELIGIBLE: ' + evidence.reason)
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, accountingReceiptSignable(receipt), keyPair.secretKey)
  return { ...receipt, signature: b4a.toString(signature, 'hex') }
}

export function verifyAccountingReceipt (receipt, opts = {}) {
  try {
    const normalized = normalizeAccountingReceipt(receipt, { signatureRequired: true })
    const ok = sodium.crypto_sign_verify_detached(
      b4a.from(normalized.signature, 'hex'),
      accountingReceiptSignable(normalized),
      b4a.from(normalized.relayPubkey, 'hex')
    )
    if (!ok) return { valid: false, evidenceEligible: false, reason: 'bad signature' }
    if (isLegacy(normalized)) {
      return {
        valid: true,
        legacy: true,
        evidenceEligible: false,
        evidenceReason: 'legacy-display-only',
        receipt: normalized
      }
    }
    const verifierNow = opts.verifierNow === undefined ? Date.now() : opts.verifierNow
    const evidence = accountingReceiptEvidence(normalized, verifierNow)
    return {
      valid: true,
      legacy: false,
      evidenceEligible: evidence.eligible,
      evidenceReason: evidence.reason,
      receipt: normalized
    }
  } catch (err) {
    return { valid: false, evidenceEligible: false, reason: err.message || String(err) }
  }
}

export function accountingReceiptEvidence (receipt, verifierNow) {
  if (!receipt || receipt.kind !== ACCOUNTING_RECEIPT_KIND || receipt.version !== ACCOUNTING_RECEIPT_VERSION) {
    return { eligible: false, reason: 'unsupported-version' }
  }
  if (!Number.isSafeInteger(verifierNow) || verifierNow < 0) {
    return { eligible: false, reason: 'invalid-verifier-time' }
  }
  const observedAt = receipt.observedAt
  const completedAt = receipt.completedAt
  if (!Number.isSafeInteger(observedAt) || !Number.isSafeInteger(completedAt) ||
      observedAt < 0 || completedAt < observedAt || completedAt > verifierNow) {
    return { eligible: false, reason: 'invalid-sample-time' }
  }
  const duration = completedAt - observedAt
  if (duration > ACCOUNTING_EPOCH_MAX_DURATION_MS) return { eligible: false, reason: 'epoch-duration-exceeded' }
  if (verifierNow - completedAt > ACCOUNTING_COMPLETION_MAX_AGE_MS) return { eligible: false, reason: 'completion-stale' }
  const observedWindow = Math.min(ACCOUNTING_OBSERVED_MAX_AGE_MS, 2 * duration + ACCOUNTING_ALLOWED_INTERVAL_MS)
  if (verifierNow - observedAt > observedWindow) return { eligible: false, reason: 'observation-stale' }
  return { eligible: true, reason: null }
}

export function accountingReceiptSignable (receipt) {
  const r = normalizeAccountingReceipt(receipt, { signatureRequired: false })
  if (isLegacy(r)) {
    return b4a.from(JSON.stringify([
      LEGACY_DOMAIN, r.kind, r.version, r.relayPubkey, r.periodStart,
      r.periodEnd, r.measuredAt, r.storageBytes, r.diskBytes,
      r.perEntryBytes, r.bytesServed, r.bytesReceived, r.leaseCount,
      r.seededCount, r.source, r.nonce
    ]), 'utf8')
  }
  return b4a.from(JSON.stringify([
    ACCOUNTING_RECEIPT_DOMAIN, r.kind, r.version, r.relayPubkey,
    r.periodStart, r.periodEnd, r.observedAt, r.completedAt,
    r.storageBytes, r.diskBytes, r.perEntryBytes, r.bytesServed,
    r.bytesReceived, r.leaseCount, r.seededCount, r.source, r.nonce
  ]), 'utf8')
}

export function normalizeAccountingReceipt (receipt, opts = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('ACCOUNTING_RECEIPT_INVALID: receipt object required')
  }
  const kind = String(receipt.kind || '')
  const version = integerField(receipt.version, 'version')
  if (kind === ACCOUNTING_RECEIPT_KIND && version === ACCOUNTING_RECEIPT_VERSION) return normalizeV2(receipt, opts)
  if (kind === LEGACY_KIND && version === LEGACY_VERSION) return normalizeV1(receipt, opts)
  throw new Error('ACCOUNTING_RECEIPT_INVALID: unsupported kind/version pair')
}

function normalizeV2 (receipt, opts) {
  assertAllowed(receipt, V2_FIELDS)
  const out = normalizeCommon(receipt)
  out.kind = ACCOUNTING_RECEIPT_KIND
  out.version = ACCOUNTING_RECEIPT_VERSION
  out.observedAt = integerField(receipt.observedAt, 'observedAt')
  out.completedAt = integerField(receipt.completedAt, 'completedAt')
  out.source = String(receipt.source || '')
  if (out.source !== ACCOUNTING_RECEIPT_SOURCE) throw new Error('ACCOUNTING_RECEIPT_INVALID: source mismatch')
  if (out.completedAt < out.observedAt) throw new Error('ACCOUNTING_RECEIPT_INVALID: completedAt before observedAt')
  if (out.observedAt < out.periodStart) throw new Error('ACCOUNTING_RECEIPT_INVALID: observedAt before periodStart')
  return finishNormalization(out, receipt, opts)
}

function normalizeV1 (receipt, opts) {
  assertAllowed(receipt, V1_FIELDS)
  const out = normalizeCommon(receipt)
  out.kind = LEGACY_KIND
  out.version = LEGACY_VERSION
  out.measuredAt = integerField(receipt.measuredAt, 'measuredAt')
  out.source = String(receipt.source || '')
  if (out.source !== LEGACY_SOURCE) throw new Error('ACCOUNTING_RECEIPT_INVALID: source mismatch')
  if (out.measuredAt < out.periodStart) throw new Error('ACCOUNTING_RECEIPT_INVALID: measuredAt before periodStart')
  return finishNormalization(out, receipt, opts)
}

function normalizeCommon (receipt) {
  return {
    relayPubkey: lowerHex(receipt.relayPubkey, HEX_32, 'relayPubkey'),
    periodStart: integerField(receipt.periodStart, 'periodStart'),
    periodEnd: integerField(receipt.periodEnd, 'periodEnd'),
    storageBytes: integerField(receipt.storageBytes, 'storageBytes'),
    diskBytes: integerField(receipt.diskBytes, 'diskBytes'),
    perEntryBytes: integerField(receipt.perEntryBytes, 'perEntryBytes'),
    bytesServed: integerField(receipt.bytesServed, 'bytesServed'),
    bytesReceived: integerField(receipt.bytesReceived, 'bytesReceived'),
    leaseCount: integerField(receipt.leaseCount, 'leaseCount'),
    seededCount: integerField(receipt.seededCount, 'seededCount'),
    nonce: lowerHex(receipt.nonce, HEX_16, 'nonce')
  }
}

function finishNormalization (out, receipt, opts) {
  if (out.periodEnd < out.periodStart) throw new Error('ACCOUNTING_RECEIPT_INVALID: periodEnd before periodStart')
  if (out.storageBytes < out.diskBytes) throw new Error('ACCOUNTING_RECEIPT_INVALID: storageBytes below diskBytes')
  if (out.storageBytes < out.perEntryBytes) throw new Error('ACCOUNTING_RECEIPT_INVALID: storageBytes below perEntryBytes')
  if (receipt.signature != null) out.signature = lowerHex(receipt.signature, HEX_SIG, 'signature')
  else if (opts.signatureRequired) throw new Error('ACCOUNTING_RECEIPT_INVALID: signature required')
  return out
}

function assertAllowed (receipt, allowed) {
  for (const key of Object.keys(receipt)) {
    if (!allowed.has(key)) throw new Error('ACCOUNTING_RECEIPT_INVALID: unknown field ' + key)
  }
}

function isLegacy (receipt) {
  return receipt.kind === LEGACY_KIND && receipt.version === LEGACY_VERSION
}

function requireKeyPair (keyPair, name) {
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) throw new Error('ACCOUNTING_RECEIPT_INVALID: ' + name + ' required')
  if (keyPair.publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) throw new Error('ACCOUNTING_RECEIPT_INVALID: bad public key')
  if (keyPair.secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) throw new Error('ACCOUNTING_RECEIPT_INVALID: bad secret key')
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
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('ACCOUNTING_RECEIPT_INVALID: bad ' + name)
  return value
}

function safeInteger (value, fallback, name) {
  if (value == null) return fallback
  return integerField(value, name)
}
