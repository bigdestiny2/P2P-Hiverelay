import { BLINDSPARK_HTTP_SURFACES } from './relaykernel-profile.js'

export const HIVEMESH_TIER_PROFILE_KIND = 'hivemesh-tier-profile'
export const HIVEMESH_TIER_PROFILE_VERSION = 1

export const HIVEMESH_TIERS = ['t1', 't2', 't3']

export const HIVEMESH_TIER_KEY_PREFIX = {
  t1: 'rk1',
  t2: 'rk2',
  t3: 'rk3'
}

const TIER_RULES = {
  t1: {
    role: 'seed-relay',
    required: ['seed', 'circuit', 'gateway', 'prove-seeded'],
    forbidden: ['custody-vault', 'tombstone-signing'],
    mustNot: {}
  },
  t2: {
    role: 'custody-vault',
    required: ['custody-receipt', 'prove-held', 'non-serving-proof'],
    forbidden: ['gateway', 'circuit', 'public-dht', 'public-directory', 'tombstone-signing'],
    mustNot: {
      gateway: true,
      circuit: true,
      publicDht: true,
      publicDirectory: true,
      storesPlaintext: true
    }
  },
  t3: {
    role: 'witness',
    required: ['tombstone-signing', 'non-serving-observation'],
    forbidden: ['seed', 'gateway', 'circuit', 'public-dht', 'custody-receipt', 'prove-held'],
    mustNot: {
      gateway: true,
      circuit: true,
      publicDht: true,
      publicDirectory: true,
      storesContent: true,
      storesPlaintext: true,
      storesCiphertext: true
    }
  }
}

export function buildHiveMeshTierProfile (opts = {}) {
  const tier = String(opts.tier || '').toLowerCase()
  const rules = TIER_RULES[tier] || null
  const capabilities = sortedStrings(opts.capabilities)
  const forbiddenPresent = rules ? rules.forbidden.filter(name => capabilities.includes(name)) : []
  const missingRequired = rules ? rules.required.filter(name => !capabilities.includes(name)) : []
  const surfaces = opts.httpGateway === true
    ? orderedUnique([
      ...BLINDSPARK_HTTP_SURFACES,
      ...arrayOfStrings(opts.httpSurfaces)
    ])
    : arrayOfStrings(opts.httpSurfaces)

  const network = {
    gateway: opts.httpGateway === true || surfaces.length > 0,
    circuit: opts.circuit === true || capabilities.includes('circuit'),
    publicDht: opts.publicDht === true || capabilities.includes('public-dht'),
    publicDirectory: opts.publicDirectory === true || capabilities.includes('public-directory'),
    httpSurfaces: surfaces
  }

  const storage = {
    storesContent: opts.storesContent === true,
    storesCiphertext: opts.storesCiphertext === true,
    storesPlaintext: opts.storesPlaintext === true
  }

  return {
    kind: HIVEMESH_TIER_PROFILE_KIND,
    version: HIVEMESH_TIER_PROFILE_VERSION,
    tier,
    role: rules ? rules.role : null,
    keyPrefix: typeof opts.keyPrefix === 'string' ? opts.keyPrefix : null,
    capabilities,
    network,
    storage,
    compatibility: {
      blindsparkHttpGateway: {
        present: includesAll(surfaces, BLINDSPARK_HTTP_SURFACES),
        surfaces
      }
    },
    ruleSummary: {
      required: rules ? rules.required : [],
      forbidden: rules ? rules.forbidden : [],
      missingRequired,
      forbiddenPresent
    }
  }
}

export function validateHiveMeshTierProfile (profile) {
  const errors = []
  const warnings = []

  if (!profile || typeof profile !== 'object') {
    return { valid: false, errors: ['profile object required'], warnings }
  }
  if (profile.kind !== HIVEMESH_TIER_PROFILE_KIND) errors.push('kind mismatch')
  if (profile.version !== HIVEMESH_TIER_PROFILE_VERSION) errors.push('version mismatch')

  const tier = String(profile.tier || '').toLowerCase()
  const rules = TIER_RULES[tier]
  if (!rules) {
    errors.push('unsupported tier: ' + (profile.tier || ''))
    return { valid: false, errors, warnings }
  }

  const expectedPrefix = HIVEMESH_TIER_KEY_PREFIX[tier]
  if (profile.keyPrefix !== expectedPrefix) {
    errors.push(`wrong key prefix for ${tier}: expected ${expectedPrefix}`)
  }

  const capabilities = arrayOfStrings(profile.capabilities)
  for (const required of rules.required) {
    if (!capabilities.includes(required)) errors.push('missing required capability: ' + required)
  }
  for (const forbidden of rules.forbidden) {
    if (capabilities.includes(forbidden)) errors.push('forbidden capability for ' + tier + ': ' + forbidden)
  }

  const network = profile.network || {}
  const storage = profile.storage || {}
  for (const [flag, forbidden] of Object.entries(rules.mustNot)) {
    const value = flag in network ? network[flag] : storage[flag]
    if (forbidden && value === true) errors.push('forbidden ' + flag + ' for ' + tier)
  }

  const gateway = profile.compatibility && profile.compatibility.blindsparkHttpGateway
  if (tier === 't1' && (!gateway || gateway.present !== true)) {
    errors.push('t1 must preserve Blindspark HTTP gateway compatibility')
  }
  if (tier !== 't1' && gateway && gateway.present === true) {
    errors.push(tier + ' must not expose Blindspark HTTP gateway surfaces')
  }

  if (tier === 't2' && storage.storesCiphertext !== true) {
    errors.push('t2 must store ciphertext')
  }
  if (tier === 't3' && capabilities.includes('bandwidth-cosign') === false) {
    warnings.push('t3 bandwidth co-signing not declared')
  }

  return { valid: errors.length === 0, errors, warnings }
}

function sortedStrings (values) {
  return orderedUnique(arrayOfStrings(values)).sort()
}

function orderedUnique (values) {
  const out = []
  const seen = new Set()
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) continue
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function arrayOfStrings (value) {
  return Array.isArray(value) ? value.filter(v => typeof v === 'string') : []
}

function includesAll (haystack, needles) {
  return needles.every(needle => haystack.includes(needle))
}
