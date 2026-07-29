function present (value) {
  if (value === undefined || value === null || value === false || value === '') return false
  if (Array.isArray(value)) return value.length > 0
  return true
}

export const MAX_HIVE_APP_PUBLIC_KEYS = 10_000
export const PUBLIC_HIVE_GATEWAY_ADMISSION_PROFILE = 'transitional-operator-allowlist-v1'
export const PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY = Object.freeze({
  kind: 'public-hive-gateway-admission-capability',
  version: 1,
  profile: PUBLIC_HIVE_GATEWAY_ADMISSION_PROFILE,
  authority: 'local-operator-allowlist',
  fleetReady: false
})
const NORMALIZED_PUBLIC_KEY_SETS = new WeakSet()

/**
 * Transitional Phase-1 admission predicate for key-derived HTTPS app hosts.
 *
 * This is deliberately stricter than the legacy path gateway. Until the blind
 * substrate owns a frozen T1 classification, a local operator-controlled
 * app-key allowlist is the independent provenance signal. Registry hydration
 * defaults alone can therefore never make a legacy row public. The predicate
 * stays isolated so the substrate can replace it without reopening the HTTP
 * serving engine.
 */
export function admitPublicHiveAppEntry (entry, opts = {}) {
  if (!entry || typeof entry !== 'object') return { allowed: false, reason: 'missing-entry' }

  const appKey = typeof opts.appKey === 'string' ? opts.appKey.toLowerCase() : ''
  const publicAppKeys = normalizeHiveAppPublicKeys(opts.publicAppKeys)
  if (!appKey || !publicAppKeys || !publicAppKeys.has(appKey)) {
    return { allowed: false, reason: 'not-operator-approved' }
  }

  if (entry.blind !== false) return { allowed: false, reason: 'not-explicitly-transparent' }
  if (String(entry.privacyTier || '').toLowerCase() !== 'public') {
    return { allowed: false, reason: 'not-explicitly-public' }
  }
  if (String(entry.storageClass || '').toLowerCase() !== 'persistent') {
    return { allowed: false, reason: 'not-persistent-availability' }
  }

  const availabilityClass = String(entry.availabilityClass || '').toLowerCase()
  if (availabilityClass !== 'always-on' && availabilityClass !== 'best-effort') {
    return { allowed: false, reason: 'not-public-availability-class' }
  }

  const custodyMarkers = [
    entry.custody,
    entry.custodyIntentId,
    entry.custodyMode,
    entry.custodyReceipt,
    entry.handoffId,
    entry.atomicHandoff,
    entry.retainUntil,
    entry.blindContentId,
    entry.encrypted,
    entry.encryption,
    entry.ciphertext,
    entry.ciphertextRoot,
    entry.commitmentRoot,
    entry.shareScheme,
    entry.shareThreshold,
    entry.shareBundleKey,
    entry.shareIndex,
    entry.shareCommitment,
    entry.shareManifest,
    entry.shareAssignments,
    entry.shardIds,
    entry.shards,
    entry.shard
  ]
  if (custodyMarkers.some(present)) return { allowed: false, reason: 'custody-or-shard-entry' }

  for (const value of [entry.contentType, entry.type]) {
    const type = String(value || '').toLowerCase()
    if (['shard', 'shard-set', 'custody', 'atomic', 'handoff', 'temporary', 'blind', 'encrypted', 'vault'].includes(type)) {
      return { allowed: false, reason: 'custody-or-shard-entry' }
    }
  }

  return { allowed: true, reason: null }
}

export function normalizeHiveAppPublicKeys (value) {
  if (value instanceof Set && NORMALIZED_PUBLIC_KEY_SETS.has(value)) return value

  const candidates = value instanceof Set ? [...value] : value
  if (!Array.isArray(candidates)) return null
  if (candidates.length > MAX_HIVE_APP_PUBLIC_KEYS) return null

  const keys = new Set()
  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || !/^[0-9a-f]{64}$/i.test(candidate)) return null
    keys.add(candidate.toLowerCase())
  }
  NORMALIZED_PUBLIC_KEY_SETS.add(keys)
  return keys
}

/**
 * Optional immutable Hyperdrive versions for public HTTPS app origins.
 *
 * The signed rollout manifest pins a drive version. Keeping the matching pin
 * in runtime config prevents a publisher update on some other path from
 * silently changing what the already-approved browser origin serves between
 * probes. An empty object remains valid for transitional staging; production
 * preflight requires a pin for every admitted key.
 */
export function normalizeHiveAppPublicVersions (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const entries = Object.entries(value)
  if (entries.length > MAX_HIVE_APP_PUBLIC_KEYS) return null

  const versions = new Map()
  for (const [candidate, version] of entries) {
    if (!/^[0-9a-f]{64}$/i.test(candidate) || !Number.isSafeInteger(version) || version < 0) return null
    const appKey = candidate.toLowerCase()
    if (versions.has(appKey)) return null
    versions.set(appKey, version)
  }
  return versions
}
