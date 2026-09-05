import b4a from 'b4a'
import {
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import {
  assertCatalogRowFitsPage,
  projectAppCatalogSource,
  validateCanonicalCatalogRow
} from './app-catalog-paged.js'

function safeNonNegativeIntegerOrNull (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function hexStringOrValue (value) {
  if (b4a.isBuffer(value)) return b4a.toString(value, 'hex')
  return value == null ? null : value
}

/**
 * Project one AppRegistry membership into the exact public catalog source
 * shape. Privacy-bearing rows remain present only through their public blind
 * identifier; hidden values are never copied into the canonical record.
 */
export function appRegistryCatalogSource (appKey, entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new TypeError('catalog registry entry must be an object')
  }
  if (entry.catalogPublic === false) {
    return Object.freeze({ catalogPublic: false, record: null })
  }

  const blind = entry.blind === true
  const rawPrivacyTier = String(entry.privacyTier || 'public').toLowerCase()
  const privacyTier = normalizePrivacyTier(entry.privacyTier, 'public')
  // Match AppRegistry._shouldRedactEntry({ redactPrivate: true }): every raw
  // non-public value, including an unknown/invalid tier that normalizes to the
  // public fallback, must fail closed instead of publishing metadata.
  const redacted = blind || rawPrivacyTier !== 'public' || entry.metadataVisibility === 'redacted'
  const seededAt = safeNonNegativeIntegerOrNull(entry.startedAt) ??
    safeNonNegativeIntegerOrNull(entry.seededAt)
  const maxStorageBytes = Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
    ? entry.maxStorage
    : null
  const durability = safeNonNegativeIntegerOrNull(entry.durability) ?? 0

  const record = {
    appKey: redacted ? null : appKey,
    appId: redacted ? null : (typeof entry.appId === 'string' && entry.appId.length > 0 ? entry.appId : null),
    type: normalizeContentType(entry.type, 'app'),
    parentKey: redacted ? null : hexStringOrValue(entry.parentKey),
    mountPath: redacted ? null : (typeof entry.mountPath === 'string' && entry.mountPath.length > 0 ? entry.mountPath : null),
    version: redacted ? null : (typeof entry.version === 'string' && entry.version.length > 0 ? entry.version : null),
    discoveryKey: redacted ? null : hexStringOrValue(entry.discoveryKey),
    blind,
    storageClass: normalizeStorageClass(entry.storageClass, blind ? 'temporary' : 'persistent'),
    availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, blind ? 'atomic-handoff' : 'always-on'),
    privacyTier,
    seededAt,
    redacted,
    metadataVisibility: redacted ? 'redacted' : 'public',
    blindContentId: redacted ? hexStringOrValue(entry.blindContentId) : null,
    anchored: entry.anchored === true,
    maxStorageBytes,
    publisherPubkey: redacted ? null : hexStringOrValue(entry.publisherPubkey),
    durability: redacted ? 0 : durability,
    revocable: redacted ? true : entry.revocable !== false,
    retainUntil: redacted ? null : safeNonNegativeIntegerOrNull(entry.retainUntil)
  }
  return Object.freeze({ catalogPublic: true, record: Object.freeze(record) })
}

/**
 * Validate a prospective registry mutation before its membership/generation
 * state changes. This is the ingress fence that prevents a newly accepted row
 * from becoming impossible to transmit in one signed PAGE.
 */
export function assertAppRegistryCatalogIngress (appKey, entry) {
  const source = appRegistryCatalogSource(appKey, entry)
  const projected = projectAppCatalogSource(source)
  if (projected.eligible) assertCatalogRowFitsPage(projected.row)
  return source
}

/**
 * Compatibility projection for the one bounded legacy type-7 fallback. It is
 * intentionally limited to fields carried by the canonical signed row.
 */
export function catalogRowToLegacyApp (input) {
  const row = validateCanonicalCatalogRow(input)
  return Object.freeze({
    appKey: row[1],
    appId: row[2],
    type: row[3],
    parentKey: row[4],
    mountPath: row[5],
    version: row[6],
    discoveryKey: row[7],
    blind: row[8],
    storageClass: row[9],
    availabilityClass: row[10],
    privacyTier: row[11],
    seededAt: row[12],
    redacted: row[13],
    metadataVisibility: row[14],
    blindContentId: row[15],
    anchored: row[16],
    maxStorageBytes: row[17],
    publisherPubkey: row[18],
    durability: row[19],
    revocable: row[20],
    retainUntil: row[21]
  })
}
