import b4a from 'b4a'
import sodium from 'sodium-universal'

export const MAX_SEED_DISCOVERY_HINTS = 64
export const SEED_DISCOVERY_HINTS_FEATURE = 'seed-discovery-hints-single-drive-v1'
export const SEED_DISCOVERY_HINTS_PROFILE = Object.freeze({
  profile: 'single-drive-v1',
  raw_max: MAX_SEED_DISCOVERY_HINTS,
  unique_max: 1,
  accepted: Object.freeze(['empty', 'canonical'])
})

const HYPERCORE_DOMAIN = b4a.from('hypercore')

function fixed32 (value) {
  if (b4a.isBuffer(value)) return value.byteLength === 32 ? value : null
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) return null
  try {
    const decoded = b4a.from(value, 'hex')
    return decoded.byteLength === 32 ? decoded : null
  } catch (_) {
    return null
  }
}

export function canonicalSeedDiscoveryHint (appKey) {
  const key = fixed32(appKey)
  if (!key) return null
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, HYPERCORE_DOMAIN, key)
  return out
}

/**
 * Validate the RC9 interpretation of the historical `discoveryKeys` field.
 * Values are routing hints for the one appKey drive, never public keys for
 * additional cores. The raw ordered list is returned unchanged so publisher
 * signature verification remains byte-exact; `unique` is the semantic view.
 */
export function validateSeedDiscoveryHints (appKey, discoveryKeys) {
  const canonical = canonicalSeedDiscoveryHint(appKey)
  if (!canonical) return { ok: false, reason: 'malformed-app-key' }
  if (!Array.isArray(discoveryKeys)) {
    return { ok: false, reason: 'malformed-discovery-key-set' }
  }
  if (discoveryKeys.length > MAX_SEED_DISCOVERY_HINTS) {
    return { ok: false, reason: 'too-many-discovery-keys' }
  }

  const raw = []
  for (const value of discoveryKeys) {
    const hint = fixed32(value)
    if (!hint) return { ok: false, reason: 'malformed-discovery-key-set' }
    raw.push(hint)
    if (!b4a.equals(hint, canonical)) {
      return { ok: false, reason: 'unsupported-discovery-key-set' }
    }
  }

  return {
    ok: true,
    raw,
    unique: raw.length === 0 ? [] : [canonical],
    canonical
  }
}
