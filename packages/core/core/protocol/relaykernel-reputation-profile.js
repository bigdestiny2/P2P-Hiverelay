export const RELAYKERNEL_REPUTATION_PROFILE_KIND = 'relaykernel-reputation-profile'
export const RELAYKERNEL_REPUTATION_PROFILE_VERSION = 1
export const RELAYKERNEL_REPUTATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000

const HEX_32 = /^[0-9a-f]{64}$/i
const MIB = 1024 * 1024

export function scoreRelayKernelReputation (input = {}, opts = {}) {
  const now = finiteNumber(input.now, finiteNumber(opts.now, Date.now()))
  const windowMs = positiveNumber(input.windowMs, positiveNumber(opts.windowMs, RELAYKERNEL_REPUTATION_WINDOW_MS))
  const rows = new Map()

  for (const relayPubkey of arrayOfStrings(input.relays)) {
    if (isHex32(relayPubkey)) getRelay(rows, relayPubkey)
  }

  for (const item of Array.isArray(input.selfAttestations) ? input.selfAttestations : []) {
    const relay = getRelay(rows, item?.relayPubkey)
    if (!relay) continue
    relay.ignored.selfAttestedUptimeHours += nonNegativeNumber(item.uptimeHours)
    relay.ignored.selfAttestedBandwidthBytes += nonNegativeNumber(item.bandwidthBytes)
  }

  for (const proof of Array.isArray(input.proofs) ? input.proofs : []) {
    if (!proof || proof.passed !== true || !inWindow(proof.at, now, windowMs)) continue
    const relay = getRelay(rows, proof.relayPubkey)
    if (!relay || !isHex32(proof.verifierPubkey)) continue
    relay.passedProofs++
    relay.verifiers.add(proof.verifierPubkey.toLowerCase())
    if (Number.isSafeInteger(proof.blockIndex) && proof.blockIndex >= 0) {
      relay.blockIndices.add(proof.blockIndex)
    }
    relay.proofAgeWeights += ageWeight(now - proof.at, windowMs)
  }

  for (const receipt of Array.isArray(input.bandwidthReceipts) ? input.bandwidthReceipts : []) {
    if (!receipt || !inWindow(receipt.at, now, windowMs)) continue
    const relay = getRelay(rows, receipt.relayPubkey)
    if (!relay) continue
    const bytes = nonNegativeNumber(receipt.bytes)
    const witnessCosigCount = countWitnessCosigs(receipt)
    if (witnessCosigCount < 1) {
      relay.ignored.unwitnessedBandwidthBytes += bytes
      continue
    }
    relay.witnessedBandwidthBytes += bytes
    relay.witnessCosigCount += witnessCosigCount
    relay.bandwidthScore += (bytes / MIB) * 0.001 * witnessCosigCount
  }

  const relays = [...rows.values()]
    .map(relay => finishRelay(relay))
    .sort((a, b) =>
      compareDesc(a.score, b.score) ||
      compareDesc(a.proofScore, b.proofScore) ||
      compareDesc(a.witnessedBandwidthScore, b.witnessedBandwidthScore) ||
      a.relayPubkey.localeCompare(b.relayPubkey)
    )

  return {
    kind: RELAYKERNEL_REPUTATION_PROFILE_KIND,
    version: RELAYKERNEL_REPUTATION_PROFILE_VERSION,
    windowMs,
    now,
    relays
  }
}

function finishRelay (relay) {
  const proofDiversityMultiplier = diversityMultiplier(relay.verifiers.size)
  const proofScore = relay.proofAgeWeights * proofDiversityMultiplier
  const witnessedBandwidthScore = relay.bandwidthScore
  const score = proofScore + witnessedBandwidthScore
  return {
    relayPubkey: relay.relayPubkey,
    score: round(score),
    proofScore: round(proofScore),
    witnessedBandwidthScore: round(witnessedBandwidthScore),
    passedProofs: relay.passedProofs,
    distinctVerifiers: relay.verifiers.size,
    distinctBlockIndices: relay.blockIndices.size,
    proofDiversityMultiplier: round(proofDiversityMultiplier),
    witnessedBandwidthBytes: relay.witnessedBandwidthBytes,
    witnessCosigCount: relay.witnessCosigCount,
    ignored: {
      selfAttestedUptimeHours: round(relay.ignored.selfAttestedUptimeHours),
      selfAttestedBandwidthBytes: relay.ignored.selfAttestedBandwidthBytes,
      unwitnessedBandwidthBytes: relay.ignored.unwitnessedBandwidthBytes
    }
  }
}

function getRelay (rows, relayPubkey) {
  if (!isHex32(relayPubkey)) return null
  const key = relayPubkey.toLowerCase()
  let relay = rows.get(key)
  if (!relay) {
    relay = {
      relayPubkey: key,
      passedProofs: 0,
      verifiers: new Set(),
      blockIndices: new Set(),
      proofAgeWeights: 0,
      witnessedBandwidthBytes: 0,
      witnessCosigCount: 0,
      bandwidthScore: 0,
      ignored: {
        selfAttestedUptimeHours: 0,
        selfAttestedBandwidthBytes: 0,
        unwitnessedBandwidthBytes: 0
      }
    }
    rows.set(key, relay)
  }
  return relay
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

function diversityMultiplier (distinctVerifiers) {
  return Math.min(1, Math.sqrt(Math.max(0, distinctVerifiers)) / 3)
}

function arrayOfStrings (value) {
  return Array.isArray(value) ? value.filter(item => typeof item === 'string') : []
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
