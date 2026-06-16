// Pure projection: public relay shapes → index rows. These take the SAME
// data the relay already publishes (catalog entries from /catalog.json, the
// signed capability doc, reputation records), so they work identically whether
// the sidecar reads them over HTTP (today) or in-process (post-hc11). No I/O.
//
// Redaction: /catalog.json is already redacted server-side, but isIndexable()
// is a defense-in-depth gate so a private/redacted entry can never become a
// row even if an upstream change ever leaked one into the feed.

const HEX64 = /^[0-9a-f]{64}$/i

function hex64 (v) {
  return typeof v === 'string' && HEX64.test(v) ? v.toLowerCase() : null
}

/**
 * Never index an entry that is private, redacted, or unkeyed. The room is a
 * public read-only mirror (no encryption key), so anything not safe for an
 * anonymous replicating peer must be dropped here.
 *
 * FAIL CLOSED on the relay's ACTUAL privacy fields — do not rely on the relay
 * having pre-redacted. The relay carries privacy in `privacyTier`
 * (public | local-first | p2p-only) and `blind`; an operator with
 * custody.redactedCatalog:false serves non-blind p2p-only/local-first entries
 * UN-redacted (real appKey/name/author/publisherPubkey, no `redacted` flag).
 * Anything not explicitly public is dropped.
 */
export function isIndexable (entry) {
  if (!entry || typeof entry !== 'object') return false
  if (entry.private === true || entry.redacted === true || entry.redact === true) return false
  if (entry.blind === true) return false
  const tier = String(entry.privacyTier || 'public').toLowerCase()
  if (tier !== 'public') return false
  if (entry.metadataVisibility === 'redacted') return false
  if (entry.visibility && entry.visibility !== 'public') return false
  return !!(hex64(entry.appKey) || hex64(entry.key) || hex64(entry.driveKey))
}

function entryKey (entry) {
  return hex64(entry.appKey) || hex64(entry.key) || hex64(entry.driveKey)
}

/**
 * Catalog entry → app-manifest row (install/launch contract). Returns null if
 * the entry is not indexable. type is the desktop's {standalone,hypersite}
 * taxonomy; the relay's own content type is preserved in catalogType.
 */
export function appManifestRow (entry) {
  if (!isIndexable(entry)) return null
  const key = entryKey(entry)
  const drive = hex64(entry.driveKey) || hex64(entry.key)
  const isSite = entry.type === 'hypersite' || entry.site === true || entry.hypersite === true
  const row = {
    appId: entry.appId || key,
    name: entry.name || entry.appId || key,
    type: isSite ? 'hypersite' : 'standalone',
    catalogType: entry.type || null,
    manifestHash: entry.manifestHash || entry.hash || undefined,
    author: entry.author || null,
    version: entry.version || null,
    icon: entry.icon || null,
    categories: Array.isArray(entry.categories) ? entry.categories : (Array.isArray(entry.tags) ? entry.tags : []),
    publisherPubkey: hex64(entry.publisherPubkey) || hex64(entry.publisher) || null,
    publishedAt: typeof entry.publishedAt === 'number' ? entry.publishedAt : (typeof entry.createdAt === 'number' ? entry.createdAt : null),
    sizeBytes: typeof entry.sizeBytes === 'number' ? entry.sizeBytes : (typeof entry.size === 'number' ? entry.size : null)
  }
  // installable and/or launchable — guarantee the anyOf(driveKey|link).
  if (drive) row.driveKey = drive
  if (entry.link) row.link = entry.link
  if (!row.driveKey && !row.link) row.link = 'hyper://' + key
  if (row.manifestHash === undefined) delete row.manifestHash
  return row
}

/**
 * Catalog entry → pin-registry row (one per appKey, the relay's seeding
 * state). seedState folds anchored/accepted; pending/rejected come from the
 * operator-authed feed (phase 2). verified is a v1 heuristic (anchored) — the
 * authoritative signal is verification rows.
 */
export function pinRegistryRow (entry, relayPubkey) {
  if (!isIndexable(entry)) return null
  const appKey = entryKey(entry)
  const anchored = entry.anchored === true
  let seedState = entry.seedState
  if (!seedState) seedState = anchored ? 'anchored' : 'accepted'
  const row = {
    appKey,
    type: entry.type || undefined,
    name: entry.name || undefined,
    version: entry.version || undefined,
    sizeBytes: typeof entry.sizeBytes === 'number' ? entry.sizeBytes : (typeof entry.size === 'number' ? entry.size : undefined),
    anchored,
    seedState,
    verified: anchored
  }
  if (typeof entry.anchoredLength === 'number') row.anchoredLength = entry.anchoredLength
  if (hex64(relayPubkey)) row.relayPubkey = hex64(relayPubkey)
  // strip undefined so additionalProperties:true rows stay clean
  for (const k of Object.keys(row)) if (row[k] === undefined) delete row[k]
  return row
}

/**
 * Capability doc (+ optional reputation record) → relay-directory row, a thin
 * signed projection. capabilitySig is the doc's own signature copied verbatim
 * so a client re-verifies the row via verifyCapabilityDoc against pubkey.
 */
export function relayDirectoryRow (doc, reputationRecord) {
  if (!doc || typeof doc !== 'object') return null
  const pubkey = hex64(doc.pubkey)
  const gatewayUrl = doc.gatewayUrl || doc.gateway || (doc.contact && doc.contact.gateway) || null
  if (!pubkey || !gatewayUrl) return null
  const cat = doc.catalog || {}
  const total = typeof cat.total === 'number' ? cat.total : 0
  const anchoredCount = typeof cat.anchored === 'number' ? cat.anchored : 0
  const lim = doc.limitation || {}
  const row = {
    pubkey,
    gatewayUrl,
    software: doc.software || null,
    version: doc.version || null,
    region: doc.region || null,
    features: Array.isArray(doc.features) ? doc.features : [],
    limitation: lim,
    health: {
      anchoredCount,
      totalCount: total,
      anchorRatio: total > 0 ? Number((anchoredCount / total).toFixed(4)) : 0,
      lastSeen: typeof doc.attestedAt === 'number' ? doc.attestedAt : 0
    },
    capacity: {
      maxStorageBytes: lim.max_storage_bytes ?? null,
      maxConnections: lim.max_connections ?? null,
      maxPendingRequests: lim.max_pending_requests ?? null
    },
    reputation: reputationRecord && typeof reputationRecord === 'object' ? reputationRecord : {},
    capabilitySig: doc.signature || null,
    // The full signed capability doc, verbatim. The projected fields above are
    // a lossy view (dropped + derived fields) so they CANNOT reconstruct the
    // signed payload; a client re-verifies by running verifyCapabilityDoc(row.doc)
    // — which has the original field set + `signature` key — and only then
    // trusts the derived view. capabilitySig is a convenience copy.
    doc
  }
  return row
}

/**
 * Normalize a verifier verdict into a verification row. Returns null if it
 * lacks the required identity/verdict fields. (Pure shaping — acceptance
 * policy + signature checking happen at write time / client-side.)
 */
export function verificationRow (input) {
  if (!input || typeof input !== 'object') return null
  const subjectAppKey = hex64(input.subjectAppKey || input.appKey)
  const verifierPubkey = hex64(input.verifierPubkey || input.verifier)
  const verdict = input.verdict
  if (!subjectAppKey || !verifierPubkey || !verdict) return null
  const row = { subjectAppKey, verifierPubkey, verdict }
  if (input.method) row.method = input.method
  if (input.anchorProofSig) row.anchorProofSig = input.anchorProofSig
  row.attestedAt = typeof input.attestedAt === 'number' ? input.attestedAt : null
  return row
}
