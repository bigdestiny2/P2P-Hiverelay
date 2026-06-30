export const HIVEMESH_TIER_REPUTATION_PROFILE_KIND = 'hivemesh-tier-reputation-profile'
export const HIVEMESH_TIER_REPUTATION_PROFILE_VERSION = 1
export const HIVEMESH_TIER_REPUTATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000
export const HIVEMESH_TIER_REPUTATION_TIERS = ['t1', 't2', 't3']

const HEX_32 = /^[0-9a-f]{64}$/i
const MIB = 1024 * 1024
const CIRCUIT_UPTIME_SECONDS_CAP = 24 * 60 * 60

export function scoreHiveMeshTierReputation (input = {}, opts = {}) {
  const now = finiteNumber(input.now, finiteNumber(opts.now, Date.now()))
  const windowMs = positiveNumber(input.windowMs, positiveNumber(opts.windowMs, HIVEMESH_TIER_REPUTATION_WINDOW_MS))
  const rows = new Map()
  const ignored = {
    unknownNodeEvidence: 0,
    crossTierEvidence: 0
  }

  for (const node of Array.isArray(input.nodes) ? input.nodes : []) {
    const normalized = normalizeNode(node)
    if (!normalized) continue
    getNode(rows, normalized)
  }

  for (const item of Array.isArray(input.selfAttestations) ? input.selfAttestations : []) {
    const node = getKnownNode(rows, item?.nodePubkey, null, ignored)
    if (!node) continue
    node.ignored.selfAttestedScore += nonNegativeNumber(item.score)
    node.ignored.selfAttestedUptimeHours += nonNegativeNumber(item.uptimeHours)
    node.ignored.selfAttestedBandwidthBytes += nonNegativeNumber(item.bandwidthBytes)
  }

  for (const proof of Array.isArray(input.t1AnchorProofs) ? input.t1AnchorProofs : []) {
    if (!proof || proof.passed !== true || !inWindow(proof.at, now, windowMs)) continue
    const node = getKnownNode(rows, proof.nodePubkey, 't1', ignored)
    if (!node || !isHex32(proof.verifierPubkey)) continue
    node.t1.proofAgeWeights += ageWeight(now - proof.at, windowMs)
    node.t1.verifiers.add(proof.verifierPubkey.toLowerCase())
    if (Number.isSafeInteger(proof.blockIndex) && proof.blockIndex >= 0) {
      node.t1.blockIndices.add(proof.blockIndex)
    }
  }

  for (const receipt of Array.isArray(input.t1BandwidthReceipts) ? input.t1BandwidthReceipts : []) {
    if (!receipt || !inWindow(receipt.at, now, windowMs)) continue
    const node = getKnownNode(rows, receipt.nodePubkey, 't1', ignored)
    if (!node) continue
    const bytes = nonNegativeNumber(receipt.bytes)
    const witnessCosigCount = countWitnessCosigs(receipt)
    if (witnessCosigCount < 1) {
      node.ignored.unwitnessedBandwidthBytes += bytes
      continue
    }
    node.t1.witnessedBandwidthBytes += bytes
    node.t1.witnessCosigCount += witnessCosigCount
    node.t1.bandwidthScore += (bytes / MIB) * 0.001 * witnessCosigCount
  }

  for (const uptime of Array.isArray(input.t1CircuitUptime) ? input.t1CircuitUptime : []) {
    if (!uptime || !inWindow(uptime.at, now, windowMs)) continue
    const node = getKnownNode(rows, uptime.nodePubkey, 't1', ignored)
    if (!node) continue
    const seconds = Math.min(nonNegativeNumber(uptime.seconds), CIRCUIT_UPTIME_SECONDS_CAP)
    node.t1.circuitUptimeSeconds += seconds
    node.t1.circuitUptimeScore += seconds * 0.0001
  }

  for (const receipt of Array.isArray(input.t2CustodyReceipts) ? input.t2CustodyReceipts : []) {
    if (!receipt || !inWindow(receipt.at, now, windowMs)) continue
    const node = getKnownNode(rows, receipt.nodePubkey, 't2', ignored)
    if (!node) continue
    node.t2.custodyReceipts++
    node.t2.custodyReceiptScore += ageWeight(now - receipt.at, windowMs)
  }

  for (const proof of Array.isArray(input.t2ProveHeld) ? input.t2ProveHeld : []) {
    if (!proof || !inWindow(proof.at, now, windowMs)) continue
    const node = getKnownNode(rows, proof.nodePubkey, 't2', ignored)
    if (!node) continue
    if (proof.passed === true) {
      const windowSeconds = positiveNumber(proof.windowSeconds, null)
      if (!windowSeconds || !isHex32(proof.verifierPubkey)) continue
      node.t2.proveHeldPasses++
      node.t2.proveHeldWindowWeight += 1 / windowSeconds
      node.t2.verifiers.add(proof.verifierPubkey.toLowerCase())
      continue
    }
    if (proof.passed === false) {
      node.t2.proveHeldMisses++
      node.t2.proveHeldMissPenalty += 5 * ageWeight(now - proof.at, windowMs)
    }
  }

  for (const claim of Array.isArray(input.t2FalseNonServingClaims) ? input.t2FalseNonServingClaims : []) {
    if (!claim || !inWindow(claim.at, now, windowMs)) continue
    const node = getKnownNode(rows, claim.nodePubkey, 't2', ignored)
    if (!node) continue
    node.t2.falseNonServingClaims++
    node.t2.falseNonServingPenalty += 50
  }

  for (const tombstone of Array.isArray(input.t3Tombstones) ? input.t3Tombstones : []) {
    if (!tombstone || !inWindow(tombstone.at, now, windowMs)) continue
    const node = getKnownNode(rows, tombstone.nodePubkey, 't3', ignored)
    if (!node) continue
    node.t3.tombstones++
    node.t3.tombstoneScore += ageWeight(now - tombstone.at, windowMs)
  }

  for (const cosig of Array.isArray(input.t3BandwidthCosigs) ? input.t3BandwidthCosigs : []) {
    if (!cosig || !inWindow(cosig.at, now, windowMs)) continue
    const node = getKnownNode(rows, cosig.nodePubkey, 't3', ignored)
    if (!node) continue
    node.t3.bandwidthCosigs++
    node.t3.bandwidthCosigScore += 0.01 * ageWeight(now - cosig.at, windowMs)
  }

  for (const slash of Array.isArray(input.t3FalseTombstoneSlashes) ? input.t3FalseTombstoneSlashes : []) {
    if (!slash || !inWindow(slash.at, now, windowMs)) continue
    const node = getKnownNode(rows, slash.nodePubkey, 't3', ignored)
    if (!node) continue
    node.t3.falseTombstones++
    node.t3.falseTombstonePenalty += 100 * ageWeight(now - slash.at, windowMs)
  }

  for (const miss of Array.isArray(input.t3LatencyMisses) ? input.t3LatencyMisses : []) {
    if (!miss || !inWindow(miss.at, now, windowMs)) continue
    const node = getKnownNode(rows, miss.nodePubkey, 't3', ignored)
    if (!node) continue
    node.t3.latencyMisses++
    node.t3.latencyMissPenalty += 2 * ageWeight(now - miss.at, windowMs)
  }

  const nodes = [...rows.values()]
  const tiers = {
    t1: finishTier(nodes, 't1'),
    t2: finishTier(nodes, 't2'),
    t3: finishTier(nodes, 't3')
  }

  return {
    kind: HIVEMESH_TIER_REPUTATION_PROFILE_KIND,
    version: HIVEMESH_TIER_REPUTATION_PROFILE_VERSION,
    now,
    windowMs,
    globalScore: null,
    tiers,
    warnings: {
      crossTierOperators: crossTierOperatorWarnings(nodes),
      verifierDisagreements: verifierDisagreementWarnings(input.verifierReports, input.verifierDisagreementThreshold)
    },
    ignored
  }
}

function finishTier (nodes, tier) {
  return nodes
    .filter(node => node.tier === tier)
    .map(node => finishNode(node, tier))
    .sort((a, b) =>
      compareDesc(a.score, b.score) ||
      a.nodePubkey.localeCompare(b.nodePubkey)
    )
}

function finishNode (node, tier) {
  if (tier === 't1') return finishT1(node)
  if (tier === 't2') return finishT2(node)
  return finishT3(node)
}

function finishT1 (node) {
  const proofDiversityMultiplier = diversityMultiplier(node.t1.verifiers.size, node.t1.blockIndices.size)
  const anchorProofScore = node.t1.proofAgeWeights * proofDiversityMultiplier
  const score = anchorProofScore + node.t1.bandwidthScore + node.t1.circuitUptimeScore
  return baseNode(node, {
    score,
    anchorProofScore,
    witnessedBandwidthScore: node.t1.bandwidthScore,
    circuitUptimeScore: node.t1.circuitUptimeScore,
    anchorProofs: node.t1.verifiers.size === 0 ? 0 : node.t1.blockIndices.size,
    distinctVerifiers: node.t1.verifiers.size,
    distinctBlockIndices: node.t1.blockIndices.size,
    proofDiversityMultiplier,
    witnessedBandwidthBytes: node.t1.witnessedBandwidthBytes,
    witnessCosigCount: node.t1.witnessCosigCount,
    circuitUptimeSeconds: node.t1.circuitUptimeSeconds
  })
}

function finishT2 (node) {
  const proveHeldDiversityMultiplier = diversityMultiplier(node.t2.verifiers.size, 0)
  const proveHeldScore = node.t2.proveHeldWindowWeight * proveHeldDiversityMultiplier
  const score = node.t2.custodyReceiptScore + proveHeldScore -
    node.t2.proveHeldMissPenalty -
    node.t2.falseNonServingPenalty
  return baseNode(node, {
    score,
    custodyReceiptScore: node.t2.custodyReceiptScore,
    proveHeldScore,
    proveHeldPenalty: node.t2.proveHeldMissPenalty,
    falseNonServingPenalty: node.t2.falseNonServingPenalty,
    custodyReceipts: node.t2.custodyReceipts,
    proveHeldPasses: node.t2.proveHeldPasses,
    proveHeldMisses: node.t2.proveHeldMisses,
    falseNonServingClaims: node.t2.falseNonServingClaims,
    distinctVerifiers: node.t2.verifiers.size,
    proveHeldDiversityMultiplier
  })
}

function finishT3 (node) {
  const score = node.t3.tombstoneScore + node.t3.bandwidthCosigScore -
    node.t3.falseTombstonePenalty -
    node.t3.latencyMissPenalty
  return baseNode(node, {
    score,
    tombstoneScore: node.t3.tombstoneScore,
    bandwidthCosigScore: node.t3.bandwidthCosigScore,
    falseTombstonePenalty: node.t3.falseTombstonePenalty,
    latencyMissPenalty: node.t3.latencyMissPenalty,
    tombstones: node.t3.tombstones,
    bandwidthCosigs: node.t3.bandwidthCosigs,
    falseTombstones: node.t3.falseTombstones,
    latencyMisses: node.t3.latencyMisses
  })
}

function baseNode (node, metrics) {
  const out = {
    nodePubkey: node.nodePubkey,
    tier: node.tier,
    keyPrefix: node.keyPrefix,
    operator: node.operator,
    region: node.region
  }
  for (const [key, value] of Object.entries(metrics)) {
    out[key] = typeof value === 'number' ? round(value) : value
  }
  out.ignored = {
    selfAttestedScore: round(node.ignored.selfAttestedScore),
    selfAttestedUptimeHours: round(node.ignored.selfAttestedUptimeHours),
    selfAttestedBandwidthBytes: node.ignored.selfAttestedBandwidthBytes,
    unwitnessedBandwidthBytes: node.ignored.unwitnessedBandwidthBytes,
    crossTierEvidence: node.ignored.crossTierEvidence
  }
  return out
}

function normalizeNode (node) {
  const tier = lowerTier(node?.tier)
  const nodePubkey = lowerHex(node?.nodePubkey || node?.pubkey)
  if (!tier || !nodePubkey) return null
  return {
    nodePubkey,
    tier,
    keyPrefix: expectedPrefix(tier),
    operator: typeof node.operator === 'string' && node.operator.length > 0 ? node.operator : null,
    region: typeof node.region === 'string' && node.region.length > 0 ? node.region : null
  }
}

function getNode (rows, normalized) {
  let node = rows.get(normalized.nodePubkey)
  if (!node) {
    node = {
      ...normalized,
      t1: {
        proofAgeWeights: 0,
        verifiers: new Set(),
        blockIndices: new Set(),
        witnessedBandwidthBytes: 0,
        witnessCosigCount: 0,
        bandwidthScore: 0,
        circuitUptimeSeconds: 0,
        circuitUptimeScore: 0
      },
      t2: {
        custodyReceipts: 0,
        custodyReceiptScore: 0,
        proveHeldPasses: 0,
        proveHeldWindowWeight: 0,
        proveHeldMisses: 0,
        proveHeldMissPenalty: 0,
        falseNonServingClaims: 0,
        falseNonServingPenalty: 0,
        verifiers: new Set()
      },
      t3: {
        tombstones: 0,
        tombstoneScore: 0,
        bandwidthCosigs: 0,
        bandwidthCosigScore: 0,
        falseTombstones: 0,
        falseTombstonePenalty: 0,
        latencyMisses: 0,
        latencyMissPenalty: 0
      },
      ignored: {
        selfAttestedScore: 0,
        selfAttestedUptimeHours: 0,
        selfAttestedBandwidthBytes: 0,
        unwitnessedBandwidthBytes: 0,
        crossTierEvidence: 0
      }
    }
    rows.set(normalized.nodePubkey, node)
  }
  return node
}

function getKnownNode (rows, pubkey, expectedTier, ignored) {
  const key = lowerHex(pubkey)
  if (!key || !rows.has(key)) {
    ignored.unknownNodeEvidence++
    return null
  }
  const node = rows.get(key)
  if (expectedTier && node.tier !== expectedTier) {
    node.ignored.crossTierEvidence++
    ignored.crossTierEvidence++
    return null
  }
  return node
}

function crossTierOperatorWarnings (nodes) {
  const byOperator = new Map()
  for (const node of nodes) {
    if (!node.operator) continue
    let entry = byOperator.get(node.operator)
    if (!entry) {
      entry = { operator: node.operator, tiers: new Set(), nodePubkeys: [] }
      byOperator.set(node.operator, entry)
    }
    entry.tiers.add(node.tier)
    entry.nodePubkeys.push(node.nodePubkey)
  }
  return [...byOperator.values()]
    .filter(entry => entry.tiers.size > 1)
    .map(entry => ({
      operator: entry.operator,
      tiers: [...entry.tiers].sort(),
      nodePubkeys: entry.nodePubkeys.sort()
    }))
    .sort((a, b) => a.operator.localeCompare(b.operator))
}

function verifierDisagreementWarnings (reports, threshold) {
  const maxDelta = positiveNumber(threshold, 10)
  const groups = new Map()
  for (const report of Array.isArray(reports) ? reports : []) {
    const nodePubkey = lowerHex(report?.nodePubkey)
    const tier = lowerTier(report?.tier)
    const verifierPubkey = lowerHex(report?.verifierPubkey)
    if (!nodePubkey || !tier || !verifierPubkey || !Number.isFinite(report.score)) continue
    const key = tier + ':' + nodePubkey
    let group = groups.get(key)
    if (!group) {
      group = { tier, nodePubkey, scores: [] }
      groups.set(key, group)
    }
    group.scores.push({
      verifierPubkey,
      score: report.score
    })
  }
  return [...groups.values()]
    .map(group => {
      const scores = group.scores.map(row => row.score)
      const min = Math.min(...scores)
      const max = Math.max(...scores)
      return {
        tier: group.tier,
        nodePubkey: group.nodePubkey,
        delta: round(max - min),
        reports: group.scores
          .map(row => ({ verifierPubkey: row.verifierPubkey, score: round(row.score) }))
          .sort((a, b) => a.verifierPubkey.localeCompare(b.verifierPubkey))
      }
    })
    .filter(group => group.reports.length > 1 && group.delta > maxDelta)
    .sort((a, b) => a.tier.localeCompare(b.tier) || a.nodePubkey.localeCompare(b.nodePubkey))
}

function countWitnessCosigs (receipt) {
  if (Number.isSafeInteger(receipt.witnessCosigCount) && receipt.witnessCosigCount >= 0) {
    return receipt.witnessCosigCount
  }
  if (!Array.isArray(receipt.witnessCosigs)) return 0
  const witnesses = new Set()
  for (const witness of receipt.witnessCosigs) {
    const value = typeof witness === 'string' ? witness : witness?.witnessPubkey
    if (isHex32(value)) witnesses.add(value.toLowerCase())
  }
  return witnesses.size
}

function inWindow (at, now, windowMs) {
  return Number.isFinite(at) && at <= now && (now - at) <= windowMs
}

function ageWeight (ageMs, windowMs) {
  return Math.exp(-ageMs / windowMs)
}

function diversityMultiplier (distinctVerifiers, distinctBlocks) {
  const diversity = distinctBlocks > 0
    ? Math.min(distinctVerifiers, distinctBlocks)
    : distinctVerifiers
  return Math.min(1, Math.sqrt(Math.max(0, diversity)) / 3)
}

function expectedPrefix (tier) {
  if (tier === 't1') return 'rk1'
  if (tier === 't2') return 'rk2'
  return 'rk3'
}

function lowerTier (value) {
  const tier = typeof value === 'string' ? value.toLowerCase() : null
  return HIVEMESH_TIER_REPUTATION_TIERS.includes(tier) ? tier : null
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

function positiveNumber (value, fallback) {
  return Number.isFinite(value) && value > 0 ? value : fallback
}

function nonNegativeNumber (value) {
  return Number.isFinite(value) && value > 0 ? value : 0
}

function compareDesc (a, b) {
  return b - a
}

function round (value) {
  return Number(value.toFixed(6))
}
