/**
 * QuorumSelector — picks geographically + organizationally diverse
 * relays for a client's read quorum.
 *
 * Implements the threat-model defense mechanism #1 (replica diversity):
 * if a client only ever talks to one relay (or to N relays controlled
 * by the same operator in the same datacenter), an attacker who
 * controls that single point can feed a consistent lie unbounded.
 * Diverse-quorum selection forces an attacker to compromise
 * geographically + organizationally separate parties simultaneously,
 * which is strictly more expensive.
 *
 * Strategies:
 *   'diverse'    — default. Picks relays maximizing distinct (region,
 *                  operator_pubkey) tuples. Falls back to whatever's
 *                  available if there isn't enough diversity in the
 *                  candidate set.
 *   'foundation' — uses a hardcoded list of foundation-network pubkeys
 *                  (the operator-of-last-resort guarantee). Useful for
 *                  apps that need a known-trusted floor.
 *   'pinned'     — uses an explicit list the caller passes in. No
 *                  diversity check; caller takes responsibility.
 *   'wide'       — uses up to N relays with no diversity constraint.
 *                  Useful for high-traffic apps that want maximum
 *                  parallelism over consistency.
 *
 * Inputs to the selector are RelayInfo records — typically obtained by
 * fetching /.well-known/hiverelay.json from candidate relays
 * (advertised via the swarm's discovery topic). The capability doc
 * gives us pubkey + region + features, which is exactly what we need.
 *
 * Pure functions, no I/O, no module-level state. The HiveRelayClient
 * does the network fetches and feeds RelayInfo into select().
 */

const VALID_STRATEGIES = ['diverse', 'foundation', 'pinned', 'wide']
const DEFAULT_QUORUM_SIZE = 5
const DEFAULT_MIN_REGIONS = 3
const DEFAULT_MIN_OPERATORS = 3

/**
 * @typedef {object} RelayInfo
 * @property {string} pubkey         relay's identity public key (hex)
 * @property {string} [region]       e.g. 'us-east-1', 'eu-west', 'asia-tokyo'
 * @property {string} [operator]     operator-controlled pubkey if distinct
 *                                   from `pubkey` (multi-relay operators)
 * @property {string[]} [features]   feature flags advertised in capability doc
 * @property {number}   [latencyMs]  observed RTT (optional; informs ranking)
 * @property {number}   [score]      operator-score (0-1 normalized; optional)
 */

/**
 * Pick a diverse quorum from a candidate set.
 *
 * @param {RelayInfo[]} candidates  - all relays we know about
 * @param {object} [opts]
 * @param {string}   [opts.strategy='diverse']
 * @param {number}   [opts.size=5]                    target quorum size
 * @param {number}   [opts.minRegions=3]              minimum distinct regions
 * @param {number}   [opts.minOperators=3]            minimum distinct operators
 * @param {string[]} [opts.foundationPubkeys=[]]      hardcoded foundation-network pubkeys
 * @param {string[]} [opts.pinnedPubkeys=[]]          explicit relay list (for 'pinned' strategy)
 * @param {string[]} [opts.requireFeatures=[]]        only consider relays advertising these
 *
 * @returns {RelayInfo[]} ordered list of selected relays (best first)
 */
export function selectQuorum (candidates, opts = {}) {
  const strategy = opts.strategy || 'diverse'
  if (!VALID_STRATEGIES.includes(strategy)) {
    throw new Error('Unknown quorum strategy: ' + strategy)
  }
  const size = opts.size || DEFAULT_QUORUM_SIZE
  const requireFeatures = opts.requireFeatures || []

  // Filter to candidates with the required feature set. A relay missing
  // a required feature can't fulfill the query at all — there's no
  // point including it in the quorum.
  let pool = (candidates || []).filter(c => c && typeof c.pubkey === 'string')
  if (requireFeatures.length > 0) {
    pool = pool.filter(c => {
      const features = Array.isArray(c.features) ? c.features : []
      return requireFeatures.every(f => features.includes(f))
    })
  }

  switch (strategy) {
    case 'pinned':
      return selectPinned(pool, opts.pinnedPubkeys || [], size)
    case 'foundation':
      return selectFoundation(pool, opts.foundationPubkeys || [], size)
    case 'wide':
      return selectWide(pool, size)
    case 'diverse':
    default:
      return selectDiverse(pool, size, opts.minRegions || DEFAULT_MIN_REGIONS, opts.minOperators || DEFAULT_MIN_OPERATORS)
  }
}

/**
 * Diverse strategy — maximize distinct (region, operator) tuples.
 *
 * Greedy, but diversity-first: at each step choose the highest-ranked
 * candidate that adds the most missing dimensions. A relay that adds a
 * new region AND a new operator beats one that adds only a region or
 * only an operator, even if its score is slightly lower. This keeps the
 * default quorum from filling with one operator's many regions while a
 * separate operator is still available.
 *
 * If all remaining candidates add no new dimensions, continue filling
 * with highest-scoring candidates — we want SOMETHING served over
 * nothing when the pool is small or concentrated.
 */
function selectDiverse (pool, size, minRegions, minOperators) {
  const ranked = [...pool].sort(byScoreDesc)
  const selected = []
  const taken = new Set()
  const seenRegions = new Set()
  const seenOperators = new Set()

  while (selected.length < size) {
    let best = null
    let bestGain = -1
    for (const r of ranked) {
      if (taken.has(r.pubkey)) continue
      const region = r.region || '__unknown__'
      const op = r.operator || r.pubkey
      const gain = (seenRegions.has(region) ? 0 : 1) + (seenOperators.has(op) ? 0 : 1)
      if (!best || gain > bestGain || (gain === bestGain && byScoreDesc(r, best) < 0)) {
        best = r
        bestGain = gain
      }
    }
    if (!best) break
    selected.push(best)
    taken.add(best.pubkey)
    seenRegions.add(best.region || '__unknown__')
    seenOperators.add(best.operator || best.pubkey)
  }

  // If we couldn't reach minRegions, the caller should know — emit a
  // diversity_warning by attaching it to the result. The HiveRelayClient
  // surfaces this as a 'quorum-warning' event so apps can decide whether
  // to wait for more candidates or proceed.
  if (selected.length > 0 && (seenRegions.size < minRegions || seenOperators.size < minOperators)) {
    const missingRegions = seenRegions.size < minRegions
    const missingOperators = seenOperators.size < minOperators
    selected.diversityWarning = {
      reason: missingRegions && missingOperators
        ? 'insufficient-quorum-diversity'
        : missingRegions
          ? 'insufficient-region-diversity'
          : 'insufficient-operator-diversity',
      observedRegions: seenRegions.size,
      requiredRegions: minRegions,
      observedOperators: seenOperators.size,
      requiredOperators: minOperators
    }
  }

  return selected
}

/**
 * Foundation strategy — restrict to a hardcoded set of trusted relay
 * pubkeys (the operator-of-last-resort layer).
 */
function selectFoundation (pool, foundationPubkeys, size) {
  const wanted = new Set(foundationPubkeys.map(p => p.toLowerCase()))
  const matched = pool
    .filter(c => wanted.has(c.pubkey.toLowerCase()))
    .sort(byScoreDesc)
  return matched.slice(0, size)
}

/**
 * Pinned strategy — exact pubkey list. Caller takes full responsibility.
 */
function selectPinned (pool, pinnedPubkeys, size) {
  const wanted = pinnedPubkeys.map(p => p.toLowerCase())
  // Preserve caller-supplied order so dependent infra can rely on it.
  const matched = []
  for (const wantedPub of wanted) {
    const found = pool.find(c => c.pubkey.toLowerCase() === wantedPub)
    if (found) matched.push(found)
    if (matched.length >= size) break
  }
  return matched
}

/**
 * Wide strategy — best-N regardless of diversity.
 */
function selectWide (pool, size) {
  return [...pool].sort(byScoreDesc).slice(0, size)
}

/**
 * Default ranking: higher operator-score first; tiebreak by lower
 * latency. Both fields are optional and only trusted inside their documented
 * bounds — relays advertising malformed or unnormalized values rank as if the
 * signal was absent. This keeps a self-reported capability doc from winning a
 * quorum by claiming Infinity, a negative RTT, or a score outside [0, 1].
 */
function byScoreDesc (a, b) {
  const sa = normalizedScore(a.score)
  const sb = normalizedScore(b.score)
  if (sb !== sa) return sb - sa
  const la = normalizedLatency(a.latencyMs)
  const lb = normalizedLatency(b.latencyMs)
  if (la !== lb) return la - lb
  return a.pubkey.localeCompare(b.pubkey)
}

function normalizedScore (score) {
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 1 ? score : 0
}

function normalizedLatency (latencyMs) {
  return typeof latencyMs === 'number' && Number.isFinite(latencyMs) && latencyMs >= 0 ? latencyMs : Infinity
}

/**
 * Lightweight summary of a quorum selection — used by client UIs and
 * the diagnostics dashboard to explain why a particular set was chosen.
 */
export function describeQuorum (selected) {
  if (!Array.isArray(selected) || selected.length === 0) {
    return { size: 0, regions: [], operators: [], warning: null }
  }
  const regions = [...new Set(selected.map(r => r.region || '__unknown__'))]
  const operators = [...new Set(selected.map(r => r.operator || r.pubkey))]
  return {
    size: selected.length,
    regions,
    operators,
    warning: selected.diversityWarning || null
  }
}

export {
  VALID_STRATEGIES,
  DEFAULT_QUORUM_SIZE,
  DEFAULT_MIN_REGIONS,
  DEFAULT_MIN_OPERATORS
}
