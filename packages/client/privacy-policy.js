/**
 * Orthogonal privacy policy + path resolver (`nym-policy-v1` / `onion-policy-v1`).
 *
 * Privacy intent is modeled as independent axes — never as a new value beside
 * the legacy `public | local-first | p2p-only` tier enum:
 *
 *   dataExposure:      'public' | 'sealed' | 'blind-custody'   — what can the handler read?
 *   transportPrivacy:  'direct' | 'source-ip-hidden' | 'traffic-analysis-resistant'
 *   identityExposure:  'stable' | 'session' | 'anonymous-reply'
 *   metadataShaping:   'none' | 'padded' | 'cover-and-mix'
 *   pathCoverage:      'full' | 'control-only' | 'none'        — required byte coverage
 *   relayLocation:     'exposed' | 'hidden-1hop' | 'hidden-onion' | 'hidden-mixnet'
 *   downgradePolicy:   'deny' | [ordered candidate ids]         — explicit fallback only
 *
 * The resolver returns an EVIDENCE-BEARING result (satisfied/unsatisfied,
 * downgraded, coverage) — never just a transport name. A required policy has
 * no implicit fallback: 'deny' fails closed, and a listed fallback is always
 * recorded as a downgrade (never silent).
 */

export const TRANSPORT_PRIVACY_ORDER = ['direct', 'source-ip-hidden', 'traffic-analysis-resistant']
export const RELAY_LOCATION_ORDER = ['exposed', 'hidden-1hop', 'hidden-onion', 'hidden-mixnet']
export const DATA_EXPOSURE = ['public', 'sealed', 'blind-custody']
export const IDENTITY_EXPOSURE = ['stable', 'session', 'anonymous-reply']
export const METADATA_SHAPING = ['none', 'padded', 'cover-and-mix']
export const PATH_COVERAGE = ['none', 'control-only', 'full']

/** Well-known candidate path ids. */
export const PATH_DIRECT = 'direct'
export const PATH_FORWARD_RELAY = 'hiverelay-forward'
export const PATH_TOR_ONION = 'tor-v3-onion-v1'
export const PATH_NYM_MIXNET = 'nym-mixnet-e2e'

function satisfies (order, offered, required) {
  return order.indexOf(offered) >= order.indexOf(required)
}

/** Validate an intent object; throws on unknown axis values. */
export function validateIntent (intent) {
  if (!intent || typeof intent !== 'object') throw new Error('privacyIntent must be an object')
  const check = (value, allowed, axis) => {
    if (value !== undefined && !allowed.includes(value)) {
      throw new Error(`invalid ${axis}: ${value}`)
    }
  }
  check(intent.dataExposure, DATA_EXPOSURE, 'dataExposure')
  check(intent.transportPrivacy, TRANSPORT_PRIVACY_ORDER, 'transportPrivacy')
  check(intent.identityExposure, IDENTITY_EXPOSURE, 'identityExposure')
  check(intent.metadataShaping, METADATA_SHAPING, 'metadataShaping')
  check(intent.pathCoverage, PATH_COVERAGE, 'pathCoverage')
  check(intent.relayLocation, RELAY_LOCATION_ORDER, 'relayLocation')
  if (intent.downgradePolicy !== undefined && intent.downgradePolicy !== 'deny' && !Array.isArray(intent.downgradePolicy)) {
    throw new Error('invalid downgradePolicy: must be "deny" or an ordered array')
  }
  return true
}

export const DEFAULT_INTENT = Object.freeze({
  dataExposure: 'sealed',
  transportPrivacy: 'direct',
  identityExposure: 'stable',
  metadataShaping: 'none',
  pathCoverage: 'full',
  relayLocation: 'exposed',
  downgradePolicy: 'deny'
})

/**
 * Resolve a privacy intent against candidate paths.
 *
 * @param {object} intent      privacyIntent (see axes above; missing = DEFAULT_INTENT)
 * @param {Array}  candidates  [{ id, available, transportPrivacy, relayLocation,
 *                             coverTraffic, coverage, notes? }]
 * @returns {object} evidence-bearing result:
 *   { selectedTransport, satisfied: [], unsatisfied: [], coverage,
 *     downgraded, reason? }
 */
export function resolvePath (intent, candidates = []) {
  const merged = { ...DEFAULT_INTENT, ...(intent || {}) }
  validateIntent(merged)

  const usable = candidates.filter((c) => c && c.available !== false)
  const evaluated = usable.map((c) => evaluateCandidate(merged, c))
  let chosen = evaluated.find((e) => e.fullySatisfied) || null
  let downgraded = false

  if (!chosen && merged.downgradePolicy !== 'deny') {
    for (const id of merged.downgradePolicy) {
      const fallback = evaluated.find((e) => e.candidate.id === id)
      if (fallback) { chosen = fallback; downgraded = true; break }
    }
    if (!chosen) {
      return {
        selectedTransport: null,
        satisfied: [],
        unsatisfied: ['no-available-fallback'],
        coverage: 'none',
        downgraded: false,
        reason: 'declared fallbacks unavailable or unevaluated'
      }
    }
  }

  if (!chosen) {
    return {
      selectedTransport: null,
      satisfied: [],
      unsatisfied: ['no-satisfying-path'],
      coverage: 'none',
      downgraded: false,
      reason: 'no candidate satisfies the intent and downgradePolicy is deny'
    }
  }

  return {
    selectedTransport: chosen.candidate.id,
    satisfied: chosen.satisfied,
    unsatisfied: chosen.unsatisfied,
    coverage: chosen.candidate.coverage || 'full',
    downgraded,
    ...(downgraded ? { downgradeFrom: merged.transportPrivacy } : {})
  }
}

function evaluateCandidate (intent, candidate) {
  const satisfied = []
  const unsatisfied = []

  if (satisfies(TRANSPORT_PRIVACY_ORDER, candidate.transportPrivacy || 'direct', intent.transportPrivacy)) {
    satisfied.push('transportPrivacy:' + intent.transportPrivacy)
  } else {
    unsatisfied.push('transportPrivacy:' + intent.transportPrivacy)
  }

  if (satisfies(RELAY_LOCATION_ORDER, candidate.relayLocation || 'exposed', intent.relayLocation)) {
    satisfied.push('relayLocation:' + intent.relayLocation)
  } else {
    unsatisfied.push('relayLocation:' + intent.relayLocation)
  }

  if (intent.metadataShaping === 'cover-and-mix') {
    if (candidate.coverTraffic) satisfied.push('metadataShaping:cover-and-mix')
    else unsatisfied.push('metadataShaping:cover-and-mix')
  } else {
    satisfied.push('metadataShaping:' + intent.metadataShaping)
  }

  // Coverage: a candidate must be able to carry at least the required bytes class.
  const cov = candidate.coverage || 'full'
  if (PATH_COVERAGE.indexOf(cov) >= PATH_COVERAGE.indexOf(intent.pathCoverage)) {
    satisfied.push('pathCoverage:' + intent.pathCoverage)
  } else {
    unsatisfied.push('pathCoverage:' + intent.pathCoverage)
  }

  return { candidate, satisfied, unsatisfied, fullySatisfied: unsatisfied.length === 0 }
}

/**
 * Translate a relay capability doc into resolver candidates, given local
 * transport availability. `local` = { direct, forwardRelay, tor, nym } booleans
 * (what THIS client can actually run right now).
 */
export function candidatesFromCapabilityDoc (doc, local = {}) {
  const candidates = []
  if (!doc || typeof doc !== 'object') return candidates

  const supported = new Set(doc.supported_transports || [])
  if (local.direct !== false && (supported.has('hyperswarm') || supported.has('websocket') || doc.gatewayUrl)) {
    candidates.push({
      id: PATH_DIRECT,
      available: true,
      transportPrivacy: 'direct',
      relayLocation: 'exposed',
      coverTraffic: false,
      coverage: 'full'
    })
  }

  if (local.forwardRelay && supported.has('hiverelay-forward')) {
    candidates.push({
      id: PATH_FORWARD_RELAY,
      available: true,
      transportPrivacy: 'source-ip-hidden',
      relayLocation: 'hidden-1hop',
      coverTraffic: false,
      coverage: 'full'
    })
  }

  for (const entry of doc.privacyTransports || []) {
    if (entry.id === PATH_TOR_ONION) {
      candidates.push({
        id: PATH_TOR_ONION,
        available: local.tor !== false,
        transportPrivacy: 'source-ip-hidden',
        relayLocation: 'hidden-onion',
        coverTraffic: false,
        coverage: 'full',
        auth: entry.auth || null,
        vports: entry.vports || []
      })
    }
    if (entry.id === PATH_NYM_MIXNET) {
      candidates.push({
        id: PATH_NYM_MIXNET,
        available: local.nym === true,
        transportPrivacy: 'traffic-analysis-resistant',
        relayLocation: 'hidden-mixnet',
        coverTraffic: true,
        coverage: 'control-only', // bounded lane; bulk rides elsewhere
        replyModes: entry.replyModes || []
      })
    }
  }

  return candidates
}
