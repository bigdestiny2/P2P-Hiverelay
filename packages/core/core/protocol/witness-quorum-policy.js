import {
  buildHiveMeshTierProfile,
  validateHiveMeshTierProfile
} from './hivemesh-tier-profile.js'

export const WITNESS_QUORUM_POLICY_KIND = 'hivemesh-witness-quorum-policy'
export const WITNESS_QUORUM_POLICY_VERSION = 1

const HEX_32 = /^[0-9a-f]{64}$/i
const REQUIRED_T3_CAPABILITIES = ['tombstone-signing', 'non-serving-observation']

export function buildWitnessQuorumPolicy (opts = {}) {
  const witnesses = normalizeWitnesses(opts.witnesses)
  const witnessCount = integerOr(opts.witnessCount, witnesses.length)
  const requiredWitnesses = integerOr(opts.requiredWitnesses, Math.min(5, witnessCount))
  return {
    kind: WITNESS_QUORUM_POLICY_KIND,
    version: WITNESS_QUORUM_POLICY_VERSION,
    intentId: lowerHexOrNull(opts.intentId),
    subjectRelayPubkey: lowerHexOrNull(opts.subjectRelayPubkey),
    publisherPubkey: lowerHexOrNull(opts.publisherPubkey),
    selectedBy: typeof opts.selectedBy === 'string' ? opts.selectedBy : 'publisher',
    witnessCount,
    requiredWitnesses,
    minOperators: integerOr(opts.minOperators, Math.min(requiredWitnesses, witnessCount)),
    minRegions: integerOr(opts.minRegions, Math.min(3, witnessCount)),
    requireT3WitnessRole: opts.requireT3WitnessRole !== false,
    witnesses,
    summary: summarizeWitnesses(witnesses)
  }
}

export function validateWitnessQuorumPolicy (policy) {
  const errors = []
  const warnings = []

  if (!policy || typeof policy !== 'object') {
    return { valid: false, errors: ['policy object required'], warnings }
  }
  if (policy.kind !== WITNESS_QUORUM_POLICY_KIND) errors.push('kind mismatch')
  if (policy.version !== WITNESS_QUORUM_POLICY_VERSION) errors.push('version mismatch')
  if (!isHex32(policy.intentId)) errors.push('intentId required')
  if (!isHex32(policy.subjectRelayPubkey)) errors.push('subjectRelayPubkey required')
  if (!isHex32(policy.publisherPubkey)) errors.push('publisherPubkey required')
  if (policy.selectedBy !== 'publisher') errors.push('witness set must be publisher-selected')

  const witnesses = Array.isArray(policy.witnesses) ? policy.witnesses : []
  const witnessCount = integerOr(policy.witnessCount, 0)
  const requiredWitnesses = integerOr(policy.requiredWitnesses, 0)
  if (witnessCount !== witnesses.length) errors.push('witnessCount does not match witness list')
  if (requiredWitnesses <= 0) errors.push('requiredWitnesses must be positive')
  if (requiredWitnesses > witnessCount) errors.push('requiredWitnesses exceeds witnessCount')
  if (!validThreshold(policy.minOperators)) errors.push('minOperators must be a non-negative integer')
  if (!validThreshold(policy.minRegions)) errors.push('minRegions must be a non-negative integer')

  const seen = new Set()
  for (const witness of witnesses) {
    if (!witness || typeof witness !== 'object') {
      errors.push('witness object required')
      continue
    }
    if (!isHex32(witness.witnessPubkey)) errors.push('bad witnessPubkey')
    else if (seen.has(witness.witnessPubkey)) errors.push('duplicate witnessPubkey: ' + witness.witnessPubkey)
    else seen.add(witness.witnessPubkey)

    if (witness.witnessPubkey === policy.subjectRelayPubkey) {
      errors.push('subject relay cannot witness itself')
    }
    if (witness.witnessPubkey === policy.publisherPubkey) {
      warnings.push('publisher is also a witness: ' + witness.witnessPubkey)
    }
    if (!witness.operator) errors.push('witness operator required')
    if (!witness.region) errors.push('witness region required')

    if (policy.requireT3WitnessRole !== false) {
      const tierVerdict = validateHiveMeshTierProfile(witness.tierProfile || buildHiveMeshTierProfile({
        tier: witness.tier,
        keyPrefix: witness.keyPrefix,
        capabilities: witness.capabilities,
        httpGateway: witness.network?.gateway === true,
        circuit: witness.network?.circuit === true,
        publicDht: witness.network?.publicDht === true,
        publicDirectory: witness.network?.publicDirectory === true,
        storesContent: witness.storage?.storesContent === true,
        storesCiphertext: witness.storage?.storesCiphertext === true,
        storesPlaintext: witness.storage?.storesPlaintext === true
      }))
      if (!tierVerdict.valid) errors.push('invalid T3 witness profile for ' + (witness.witnessPubkey || 'unknown'))
    }
  }

  const summary = summarizeWitnesses(witnesses)
  if (summary.operators.length < integerOr(policy.minOperators, 0)) {
    errors.push('insufficient witness operator diversity')
  }
  if (summary.regions.length < integerOr(policy.minRegions, 0)) {
    errors.push('insufficient witness region diversity')
  }

  return { valid: errors.length === 0, errors, warnings }
}

export function evaluateWitnessQuorum (policy, entries = []) {
  const policyVerdict = validateWitnessQuorumPolicy(policy)
  if (!policyVerdict.valid) {
    return { valid: false, count: 0, required: integerOr(policy?.requiredWitnesses, 0), accepted: [], rejected: [], reason: 'invalid-policy' }
  }

  const selected = new Set(policy.witnesses.map(witness => witness.witnessPubkey))
  const accepted = []
  const rejected = []
  const seen = new Set()

  for (const entry of Array.isArray(entries) ? entries : []) {
    const witnessPubkey = lowerHexOrNull(entry?.witnessPubkey)
    const reason = rejectWitnessEntry(policy, selected, seen, entry, witnessPubkey)
    if (reason) {
      rejected.push({ witnessPubkey, reason })
      continue
    }
    seen.add(witnessPubkey)
    accepted.push(witnessPubkey)
  }

  const required = policy.requiredWitnesses
  return {
    valid: accepted.length >= required,
    count: accepted.length,
    required,
    accepted,
    rejected,
    reason: accepted.length >= required ? null : 'witness-quorum-not-reached'
  }
}

function rejectWitnessEntry (policy, selected, seen, entry, witnessPubkey) {
  if (!entry || typeof entry !== 'object') return 'entry required'
  if (!isHex32(witnessPubkey)) return 'bad witnessPubkey'
  if (!selected.has(witnessPubkey)) return 'witness not publisher-selected'
  if (seen.has(witnessPubkey)) return 'duplicate witness'
  if (entry.intentId !== policy.intentId) return 'intentId mismatch'
  if (entry.relayPubkey !== policy.subjectRelayPubkey) return 'subject relay mismatch'
  if (entry.catalogPresent || entry.gatewayServing || entry.activeSwarmObserved) return 'witness observed active serving'
  return null
}

function normalizeWitnesses (witnesses) {
  return (Array.isArray(witnesses) ? witnesses : [])
    .map(witness => {
      const witnessPubkey = lowerHexOrNull(witness?.witnessPubkey)
      const operator = typeof witness?.operator === 'string' ? witness.operator : null
      const region = typeof witness?.region === 'string' ? witness.region : null
      const out = {
        witnessPubkey,
        operator,
        region,
        tier: typeof witness?.tier === 'string' ? witness.tier : 't3',
        keyPrefix: typeof witness?.keyPrefix === 'string' ? witness.keyPrefix : 'rk3',
        capabilities: sortedStrings(witness?.capabilities || REQUIRED_T3_CAPABILITIES),
        network: {
          gateway: witness?.network?.gateway === true,
          circuit: witness?.network?.circuit === true,
          publicDht: witness?.network?.publicDht === true,
          publicDirectory: witness?.network?.publicDirectory === true
        },
        storage: {
          storesContent: witness?.storage?.storesContent === true,
          storesCiphertext: witness?.storage?.storesCiphertext === true,
          storesPlaintext: witness?.storage?.storesPlaintext === true
        }
      }
      if (witness?.tierProfile) out.tierProfile = witness.tierProfile
      return out
    })
    .sort((a, b) => String(a.witnessPubkey).localeCompare(String(b.witnessPubkey)))
}

function summarizeWitnesses (witnesses) {
  const rows = witnesses.filter(witness => witness && typeof witness === 'object')
  return {
    operators: uniqueSorted(rows.map(witness => witness.operator).filter(Boolean)),
    regions: uniqueSorted(rows.map(witness => witness.region).filter(Boolean))
  }
}

function uniqueSorted (values) {
  return [...new Set(values)].sort()
}

function sortedStrings (values) {
  return Array.isArray(values) ? [...new Set(values.filter(value => typeof value === 'string'))].sort() : []
}

function lowerHexOrNull (value) {
  if (typeof value !== 'string') return null
  const out = value.toLowerCase()
  return HEX_32.test(out) ? out : null
}

function isHex32 (value) {
  return typeof value === 'string' && HEX_32.test(value)
}

function integerOr (value, fallback) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback
}

function validThreshold (value) {
  return Number.isSafeInteger(value) && value >= 0
}
