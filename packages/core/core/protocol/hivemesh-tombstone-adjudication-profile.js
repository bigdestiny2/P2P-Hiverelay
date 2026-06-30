import {
  buildWitnessQuorumPolicy,
  validateWitnessQuorumPolicy
} from './witness-quorum-policy.js'

export const HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_KIND = 'hivemesh-tombstone-adjudication-profile'
export const HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_VERSION = 1
export const HIVEMESH_TOMBSTONE_ADJUDICATION_OBSERVATION_GRACE_MS = 30 * 1000
export const HIVEMESH_TOMBSTONE_ADJUDICATION_MAX_CLOCK_SKEW_MS = 30 * 1000
export const HIVEMESH_TOMBSTONE_ADJUDICATION_CONTRADICTION_WINDOW_MS = 2 * 60 * 1000

const HEX_32 = /^[0-9a-f]{64}$/i
const DEFAULT_MIN_ATTEMPTS = 2
const DEFAULT_MIN_CONTRADICTION_STRENGTH = 3

const SERVING_EVIDENCE_STRENGTH = Object.freeze({
  'retrievability-proof': 3,
  'gateway-range-proof': 2,
  'gateway-range-206': 2,
  'catalog-present': 1,
  'active-swarm-observed': 1
})

export function evaluateHiveMeshTombstoneAdjudicationProfile (input = {}, opts = {}) {
  const now = finiteNumber(input.now, finiteNumber(opts.now, Date.now()))
  const intent = normalizeIntent(input.intent || input)
  const witnessPolicy = normalizeWitnessPolicy(input.witnessPolicy, intent)
  const witnessPolicyVerdict = validateWitnessQuorumPolicy(witnessPolicy)
  const adjudicationPolicy = normalizeAdjudicationPolicy(input.adjudicationPolicy, opts, witnessPolicy)
  const nonServingProofs = normalizeNonServingProofs(input.nonServingProofs)
  const tombstoneQuorum = evaluateTombstoneQuorum({
    entries: input.tombstones,
    intent,
    now,
    witnessPolicy,
    witnessPolicyVerdict,
    nonServingProofs,
    adjudicationPolicy
  })
  const contradiction = evaluateServingContradiction({
    entries: input.servingEvidence,
    intent,
    now,
    tombstoneQuorum,
    adjudicationPolicy
  })

  return {
    kind: HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_KIND,
    version: HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_VERSION,
    now,
    intent,
    adjudicationPolicy,
    witnessPolicyVerdict,
    tombstoneQuorum,
    contradiction,
    verdict: buildVerdict(witnessPolicyVerdict, tombstoneQuorum, contradiction)
  }
}

function evaluateTombstoneQuorum ({
  entries,
  intent,
  now,
  witnessPolicy,
  witnessPolicyVerdict,
  nonServingProofs,
  adjudicationPolicy
}) {
  const required = adjudicationPolicy.requiredWitnesses
  const rejected = []

  if (!witnessPolicyVerdict.valid) {
    return {
      valid: false,
      count: 0,
      required,
      challengeNonce: null,
      operators: [],
      regions: [],
      accepted: [],
      rejected,
      groups: [],
      reason: 'invalid-witness-policy'
    }
  }

  const selected = new Map(witnessPolicy.witnesses.map(witness => [witness.witnessPubkey, witness]))
  const seen = new Set()
  const accepted = []

  for (const entry of Array.isArray(entries) ? entries : []) {
    const normalized = normalizeTombstoneEntry(entry)
    const reason = rejectTombstoneEntry({
      entry: normalized,
      intent,
      now,
      selected,
      seen,
      nonServingProofs,
      adjudicationPolicy
    })
    if (reason) {
      rejected.push({
        witnessPubkey: normalized.witnessPubkey,
        challengeNonce: normalized.challengeNonce,
        reason
      })
      continue
    }

    const witness = selected.get(normalized.witnessPubkey)
    seen.add(normalized.witnessPubkey + ':' + normalized.challengeNonce)
    accepted.push({
      witnessPubkey: normalized.witnessPubkey,
      operator: witness.operator,
      region: witness.region,
      at: normalized.at,
      challengeNonce: normalized.challengeNonce,
      attempts: normalized.attempts,
      nonServingProofHash: normalized.nonServingProofHash
    })
  }

  accepted.sort(compareChallengeWitness)
  const groups = buildTombstoneGroups(accepted, adjudicationPolicy)
  const quorumGroup = groups.find(group => group.valid) || null

  return {
    valid: !!quorumGroup,
    count: quorumGroup ? quorumGroup.count : 0,
    required,
    challengeNonce: quorumGroup ? quorumGroup.challengeNonce : null,
    operators: quorumGroup ? quorumGroup.operators : [],
    regions: quorumGroup ? quorumGroup.regions : [],
    accepted,
    rejected: rejected.sort(compareRejected),
    groups,
    reason: quorumGroup ? null : bestTombstoneReason(groups, accepted.length)
  }
}

function rejectTombstoneEntry ({
  entry,
  intent,
  now,
  selected,
  seen,
  nonServingProofs,
  adjudicationPolicy
}) {
  if (!entry.source) return 'entry required'
  if (!isHex32(intent.intentId)) return 'intentId required'
  if (!isHex32(intent.relayPubkey)) return 'relayPubkey required'
  if (!Number.isFinite(intent.retainUntil)) return 'retainUntil required'
  if (!isHex32(entry.witnessPubkey)) return 'bad witnessPubkey'
  if (!selected.has(entry.witnessPubkey)) return 'witness not publisher-selected'
  if (!isHex32(entry.challengeNonce)) return 'bad challengeNonce'
  if (seen.has(entry.witnessPubkey + ':' + entry.challengeNonce)) return 'duplicate witness challenge'
  if (entry.intentId !== intent.intentId) return 'intentId mismatch'
  if (entry.relayPubkey !== intent.relayPubkey) return 'subject relay mismatch'
  if (!Number.isFinite(entry.at)) return 'timestamp required'
  if (entry.at < intent.retainUntil + adjudicationPolicy.observationGraceMs) return 'observation before expiry grace'
  if (entry.at > now + adjudicationPolicy.maxClockSkewMs) return 'timestamp too far in future'
  if (entry.attempts < adjudicationPolicy.minAttempts) return 'retry policy not met'
  if (!isHex32(entry.nonServingProofHash)) return 'nonServingProofHash required'
  if (adjudicationPolicy.requireKnownNonServingProof) {
    const proof = nonServingProofs.get(entry.nonServingProofHash)
    if (!proof) return 'matching non-serving proof required'
    if (!proof.notServing) return 'non-serving proof did not prove non-serving'
    if (proof.intentId !== intent.intentId || proof.relayPubkey !== intent.relayPubkey || proof.challengeNonce !== entry.challengeNonce) {
      return 'non-serving proof scope mismatch'
    }
    if (proof.at < intent.retainUntil + adjudicationPolicy.observationGraceMs) return 'non-serving proof before expiry grace'
    if (proof.at > entry.at + adjudicationPolicy.maxClockSkewMs) return 'non-serving proof after witness observation'
    if (proof.catalogPresent || proof.activeSwarmServing) return 'non-serving proof reports active serving'
  }
  if (entry.catalogPresent || entry.gatewayServing || entry.activeSwarmObserved) return 'witness observed active serving'
  return null
}

function buildTombstoneGroups (accepted, adjudicationPolicy) {
  const byChallenge = new Map()
  for (const entry of accepted) {
    let group = byChallenge.get(entry.challengeNonce)
    if (!group) {
      group = {
        challengeNonce: entry.challengeNonce,
        entries: [],
        operators: new Set(),
        regions: new Set(),
        firstObservedAt: entry.at,
        lastObservedAt: entry.at
      }
      byChallenge.set(entry.challengeNonce, group)
    }
    group.entries.push(entry)
    group.operators.add(entry.operator)
    group.regions.add(entry.region)
    group.firstObservedAt = Math.min(group.firstObservedAt, entry.at)
    group.lastObservedAt = Math.max(group.lastObservedAt, entry.at)
  }

  return [...byChallenge.values()]
    .map(group => {
      const operators = uniqueSorted([...group.operators].filter(Boolean))
      const regions = uniqueSorted([...group.regions].filter(Boolean))
      const out = {
        challengeNonce: group.challengeNonce,
        count: group.entries.length,
        required: adjudicationPolicy.requiredWitnesses,
        operators,
        regions,
        firstObservedAt: group.firstObservedAt,
        lastObservedAt: group.lastObservedAt
      }
      out.valid = groupValid(out, adjudicationPolicy)
      out.reason = out.valid ? null : groupReason(out, adjudicationPolicy)
      return out
    })
    .sort((a, b) =>
      Number(b.valid) - Number(a.valid) ||
      b.count - a.count ||
      a.challengeNonce.localeCompare(b.challengeNonce)
    )
}

function evaluateServingContradiction ({
  entries,
  intent,
  now,
  tombstoneQuorum,
  adjudicationPolicy
}) {
  const rejected = []
  const accepted = []
  const challengeNonce = tombstoneQuorum.challengeNonce
  const group = tombstoneQuorum.groups.find(group => group.challengeNonce === challengeNonce) || null

  if (!tombstoneQuorum.valid || !group) {
    return {
      valid: false,
      challengeNonce: null,
      totalStrength: 0,
      distinctObservers: 0,
      accepted,
      rejected,
      reason: 'no-valid-tombstone-quorum'
    }
  }

  for (const entry of Array.isArray(entries) ? entries : []) {
    const normalized = normalizeServingEvidence(entry)
    const reason = rejectServingEvidence({
      entry: normalized,
      intent,
      now,
      challengeNonce,
      group,
      adjudicationPolicy
    })
    if (reason) {
      rejected.push({
        observerPubkey: normalized.observerPubkey,
        challengeNonce: normalized.challengeNonce,
        reason
      })
      continue
    }
    accepted.push({
      observerPubkey: normalized.observerPubkey,
      type: normalized.type,
      at: normalized.at,
      challengeNonce: normalized.challengeNonce,
      strength: normalized.strength
    })
  }

  accepted.sort((a, b) =>
    a.at - b.at ||
    a.observerPubkey.localeCompare(b.observerPubkey) ||
    a.type.localeCompare(b.type)
  )

  const totalStrength = accepted.reduce((sum, entry) => sum + entry.strength, 0)
  const distinctObservers = uniqueSorted(accepted.map(entry => entry.observerPubkey)).length
  const valid = totalStrength >= adjudicationPolicy.minContradictionStrength

  return {
    valid,
    challengeNonce,
    totalStrength,
    distinctObservers,
    accepted,
    rejected: rejected.sort(compareRejected),
    reason: valid ? null : 'insufficient-serving-contradiction'
  }
}

function rejectServingEvidence ({
  entry,
  intent,
  now,
  challengeNonce,
  group,
  adjudicationPolicy
}) {
  if (!entry.source) return 'entry required'
  if (entry.intentId !== intent.intentId) return 'intentId mismatch'
  if (entry.relayPubkey !== intent.relayPubkey) return 'subject relay mismatch'
  if (entry.challengeNonce !== challengeNonce) return 'challengeNonce mismatch'
  if (!isHex32(entry.observerPubkey)) return 'bad observerPubkey'
  if (!Number.isFinite(entry.at)) return 'timestamp required'
  if (entry.at < group.firstObservedAt - adjudicationPolicy.maxClockSkewMs) return 'evidence before tombstone challenge'
  if (entry.at > group.lastObservedAt + adjudicationPolicy.contradictionWindowMs) return 'evidence outside contradiction window'
  if (entry.at > now + adjudicationPolicy.maxClockSkewMs) return 'timestamp too far in future'
  if (!entry.success) return 'serving evidence did not prove serving'
  if (entry.strength <= 0) return 'unsupported serving evidence type'
  return null
}

function buildVerdict (witnessPolicyVerdict, tombstoneQuorum, contradiction) {
  if (!witnessPolicyVerdict.valid) {
    return {
      status: 'invalid-witness-policy',
      markRelayExpired: false,
      slashWitnesses: [],
      reason: 'invalid-witness-policy'
    }
  }
  if (!tombstoneQuorum.valid) {
    return {
      status: 'insufficient-tombstone-quorum',
      markRelayExpired: false,
      slashWitnesses: [],
      reason: tombstoneQuorum.reason
    }
  }
  if (contradiction.valid) {
    return {
      status: 'false-tombstone',
      markRelayExpired: false,
      slashWitnesses: tombstoneQuorum.accepted
        .filter(entry => entry.challengeNonce === tombstoneQuorum.challengeNonce)
        .map(entry => entry.witnessPubkey)
        .sort(),
      reason: 'serving evidence contradicted tombstone quorum'
    }
  }
  return {
    status: 'non-serving-confirmed',
    markRelayExpired: true,
    slashWitnesses: [],
    reason: null
  }
}

function normalizeIntent (source) {
  return {
    intentId: lowerHex(source?.intentId),
    relayPubkey: lowerHex(source?.relayPubkey || source?.subjectRelayPubkey),
    retainUntil: finiteNumber(source?.retainUntil, null)
  }
}

function normalizeWitnessPolicy (source, intent) {
  const policy = source && typeof source === 'object' ? source : {}
  if (policy.kind) return policy
  return buildWitnessQuorumPolicy({
    ...policy,
    intentId: policy.intentId || intent.intentId,
    subjectRelayPubkey: policy.subjectRelayPubkey || intent.relayPubkey
  })
}

function normalizeAdjudicationPolicy (source, opts, witnessPolicy) {
  const policy = source && typeof source === 'object' ? source : {}
  const requiredWitnesses = positiveInteger(
    policy.requiredWitnesses,
    positiveInteger(opts.requiredWitnesses, positiveInteger(witnessPolicy.requiredWitnesses, 1))
  )
  return {
    requiredWitnesses,
    minOperators: positiveInteger(
      policy.minOperators,
      positiveInteger(opts.minOperators, positiveInteger(witnessPolicy.minOperators, requiredWitnesses))
    ),
    minRegions: positiveInteger(
      policy.minRegions,
      positiveInteger(opts.minRegions, positiveInteger(witnessPolicy.minRegions, 1))
    ),
    minAttempts: positiveInteger(policy.minAttempts, positiveInteger(opts.minAttempts, DEFAULT_MIN_ATTEMPTS)),
    requireKnownNonServingProof: policy.requireKnownNonServingProof !== false &&
      opts.requireKnownNonServingProof !== false,
    observationGraceMs: nonNegativeInteger(
      policy.observationGraceMs,
      nonNegativeInteger(opts.observationGraceMs, HIVEMESH_TOMBSTONE_ADJUDICATION_OBSERVATION_GRACE_MS)
    ),
    maxClockSkewMs: nonNegativeInteger(
      policy.maxClockSkewMs,
      nonNegativeInteger(opts.maxClockSkewMs, HIVEMESH_TOMBSTONE_ADJUDICATION_MAX_CLOCK_SKEW_MS)
    ),
    contradictionWindowMs: positiveInteger(
      policy.contradictionWindowMs,
      positiveInteger(opts.contradictionWindowMs, HIVEMESH_TOMBSTONE_ADJUDICATION_CONTRADICTION_WINDOW_MS)
    ),
    minContradictionStrength: positiveInteger(
      policy.minContradictionStrength,
      positiveInteger(opts.minContradictionStrength, DEFAULT_MIN_CONTRADICTION_STRENGTH)
    )
  }
}

function normalizeNonServingProofs (entries) {
  const proofs = new Map()
  for (const entry of Array.isArray(entries) ? entries : []) {
    const proof = normalizeNonServingProof(entry)
    if (!isHex32(proof.proofHash)) continue
    proofs.set(proof.proofHash, proof)
  }
  return proofs
}

function normalizeNonServingProof (entry) {
  const source = entry && typeof entry === 'object' ? entry : null
  return {
    proofHash: lowerHex(source?.proofHash || source?.hash || source?.nonServingProofHash),
    intentId: lowerHex(source?.intentId),
    relayPubkey: lowerHex(source?.relayPubkey),
    challengeNonce: lowerHex(source?.challengeNonce),
    at: finiteNumber(source?.at, finiteNumber(source?.timestamp, null)),
    notServing: source?.notServing === true,
    catalogPresent: source?.catalogPresent === true,
    activeSwarmServing: source?.activeSwarmServing === true
  }
}

function normalizeTombstoneEntry (entry) {
  const source = entry && typeof entry === 'object' ? entry : null
  return {
    source,
    intentId: lowerHex(source?.intentId),
    relayPubkey: lowerHex(source?.relayPubkey),
    witnessPubkey: lowerHex(source?.witnessPubkey),
    at: finiteNumber(source?.at, finiteNumber(source?.timestamp, null)),
    challengeNonce: lowerHex(source?.challengeNonce),
    attempts: nonNegativeInteger(source?.attempts, 1),
    nonServingProofHash: lowerHex(source?.nonServingProofHash),
    catalogPresent: source?.catalogPresent === true,
    gatewayServing: source?.gatewayServing === true,
    activeSwarmObserved: source?.activeSwarmObserved === true
  }
}

function normalizeServingEvidence (entry) {
  const source = entry && typeof entry === 'object' ? entry : null
  const type = typeof source?.type === 'string' ? source.type : null
  return {
    source,
    intentId: lowerHex(source?.intentId),
    relayPubkey: lowerHex(source?.relayPubkey),
    observerPubkey: lowerHex(source?.observerPubkey),
    challengeNonce: lowerHex(source?.challengeNonce),
    at: finiteNumber(source?.at, finiteNumber(source?.timestamp, null)),
    type,
    success: source?.success === true ||
      source?.gatewayServing === true ||
      source?.catalogPresent === true ||
      source?.activeSwarmServing === true,
    strength: positiveInteger(source?.strength, SERVING_EVIDENCE_STRENGTH[type] || 0)
  }
}

function groupValid (group, policy) {
  return group.count >= policy.requiredWitnesses &&
    group.operators.length >= policy.minOperators &&
    group.regions.length >= policy.minRegions
}

function groupReason (group, policy) {
  if (group.count < policy.requiredWitnesses) return 'tombstone-quorum-not-reached'
  if (group.operators.length < policy.minOperators) return 'insufficient-witness-operator-diversity'
  if (group.regions.length < policy.minRegions) return 'insufficient-witness-region-diversity'
  return null
}

function bestTombstoneReason (groups, acceptedCount) {
  if (acceptedCount === 0) return 'no-accepted-tombstones'
  return groups[0]?.reason || 'tombstone-quorum-not-reached'
}

function compareChallengeWitness (a, b) {
  return a.challengeNonce.localeCompare(b.challengeNonce) ||
    a.witnessPubkey.localeCompare(b.witnessPubkey)
}

function compareRejected (a, b) {
  return String(a.challengeNonce).localeCompare(String(b.challengeNonce)) ||
    String(a.witnessPubkey || a.observerPubkey).localeCompare(String(b.witnessPubkey || b.observerPubkey)) ||
    a.reason.localeCompare(b.reason)
}

function uniqueSorted (values) {
  return [...new Set(values)].sort()
}

function lowerHex (value) {
  if (typeof value !== 'string' || !HEX_32.test(value)) return null
  return value.toLowerCase()
}

function isHex32 (value) {
  return typeof value === 'string' && HEX_32.test(value)
}

function finiteNumber (value, fallback) {
  return Number.isFinite(value) ? value : fallback
}

function positiveInteger (value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

function nonNegativeInteger (value, fallback) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback
}
