export const RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND = 'relaykernel-circuit-limits-profile'
export const RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_VERSION = 1

export const RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS = 10 * 60 * 1000
export const RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP = 64 * 1024 * 1024
export const RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP = 5
export const RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP = 64 * 1024
export const RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS = 1024 * 1024

const RELAYKERNEL_CHANNEL = 'rk-circuit'
const HIVEMESH_T1_CHANNEL = 't1-circuit'
const HIVERELAY_COMPAT_CHANNEL = 'hiverelay-circuit'
const CIRCUIT_CLIENT_ROLES = ['rkc']
const RELAY_SERVER_ROLES = ['rk1']

export function evaluateRelayKernelCircuitLimitsProfile (input = {}, opts = {}) {
  const runtime = normalizeRuntime(input.runtime, opts)
  const limits = normalizeLimits(input.limits, runtime)
  const channels = normalizeChannels(input.channels)
  const limitChecks = evaluateLimitChecks(limits, runtime)
  const securityChecks = evaluateSecurityChecks(runtime)
  const warnings = [
    ...limitChecks.warnings,
    ...securityChecks.warnings,
    ...evaluateChannelWarnings(channels)
  ].sort()
  const errors = [
    ...limitChecks.errors,
    ...securityChecks.errors
  ].sort()
  const decisions = evaluateDecisions(input.decisions, { limits, runtime, channels })

  return {
    kind: RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND,
    version: RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_VERSION,
    hardCaps: {
      maxSessionMs: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      maxBytes: RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
      maxCircuitsPerPeer: RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
      maxFrameBytes: RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
      recommendedRateBytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
    },
    channels,
    limits,
    runtime,
    limitChecks: limitChecks.checks,
    securityChecks: securityChecks.checks,
    decisions,
    verdict: {
      valid: errors.length === 0 && decisions.every(decision => decision.accepted === decision.expectedAccepted),
      errors,
      warnings
    }
  }
}

function normalizeRuntime (runtime = {}, opts = {}) {
  return {
    reserveAuthBindsRemoteKey: bool(runtime.reserveAuthBindsRemoteKey, bool(opts.reserveAuthBindsRemoteKey, false)),
    connectAuthBindsRemoteKey: bool(runtime.connectAuthBindsRemoteKey, bool(opts.connectAuthBindsRemoteKey, false)),
    endpointOnlyData: bool(runtime.endpointOnlyData, bool(opts.endpointOnlyData, false)),
    closeOnFrameTooLarge: bool(runtime.closeOnFrameTooLarge, bool(opts.closeOnFrameTooLarge, false)),
    closeOnByteCap: bool(runtime.closeOnByteCap, bool(opts.closeOnByteCap, false)),
    silentDropUnknownCircuit: bool(runtime.silentDropUnknownCircuit, bool(opts.silentDropUnknownCircuit, false)),
    relayAccountingEnabled: bool(runtime.relayAccountingEnabled, bool(opts.relayAccountingEnabled, false)),
    relayMaxCircuitDurationMs: positiveInteger(runtime.relayMaxCircuitDurationMs, positiveInteger(opts.relayMaxCircuitDurationMs, null)),
    circuitRelayCleanupMs: positiveInteger(runtime.circuitRelayCleanupMs, positiveInteger(opts.circuitRelayCleanupMs, null)),
    perCircuitRateCapBytesPerSecond: positiveInteger(
      runtime.perCircuitRateCapBytesPerSecond,
      positiveInteger(opts.perCircuitRateCapBytesPerSecond, null)
    )
  }
}

function normalizeLimits (limits = {}, runtime) {
  return {
    maxSessionMs: positiveInteger(limits.maxSessionMs, runtime.relayMaxCircuitDurationMs),
    maxBytes: positiveInteger(limits.maxBytes, RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP),
    maxCircuitsPerPeer: positiveInteger(limits.maxCircuitsPerPeer, RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP),
    maxFrameBytes: positiveInteger(limits.maxFrameBytes, RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP),
    maxPendingConnects: positiveInteger(limits.maxPendingConnects, null),
    maxReservePerMinute: positiveInteger(limits.maxReservePerMinute, null),
    rateCapBytesPerSecond: positiveInteger(limits.rateCapBytesPerSecond, runtime.perCircuitRateCapBytesPerSecond)
  }
}

function normalizeChannels (channels) {
  const values = orderedUnique(Array.isArray(channels) ? channels : [HIVERELAY_COMPAT_CHANNEL])
  return {
    kernel: values.includes(RELAYKERNEL_CHANNEL),
    hivemeshT1: values.includes(HIVEMESH_T1_CHANNEL),
    hiverelayCompat: values.includes(HIVERELAY_COMPAT_CHANNEL),
    advertised: values
  }
}

function evaluateLimitChecks (limits, runtime) {
  const checks = {
    sessionHardCap: limits.maxSessionMs <= RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
    byteHardCap: limits.maxBytes <= RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
    concurrentHardCap: limits.maxCircuitsPerPeer <= RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
    frameHardCap: limits.maxFrameBytes <= RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
    reserveRateLimited: Number.isSafeInteger(limits.maxReservePerMinute) && limits.maxReservePerMinute > 0,
    pendingConnectsBounded: Number.isSafeInteger(limits.maxPendingConnects) && limits.maxPendingConnects > 0,
    perCircuitRateCapped: Number.isSafeInteger(limits.rateCapBytesPerSecond) &&
      limits.rateCapBytesPerSecond <= RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
    relayAccountingDurationCap: runtime.relayAccountingEnabled === true &&
      runtime.relayMaxCircuitDurationMs <= RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS
  }
  const errors = []
  const warnings = []

  if (!checks.byteHardCap) errors.push('circuit byte cap exceeds 64 MiB hard cap')
  if (!checks.concurrentHardCap) errors.push('per-peer circuit cap exceeds 5 hard cap')
  if (!checks.frameHardCap) errors.push('circuit frame cap exceeds 64 KiB hard cap')
  if (!checks.sessionHardCap && !checks.relayAccountingDurationCap) {
    errors.push('circuit session cap exceeds 10 minute hard cap')
  }
  if (!checks.sessionHardCap && checks.relayAccountingDurationCap) {
    warnings.push('standalone CircuitRelay cleanup exceeds 10 minute hard cap; Relay accounting supplies the cap')
  }
  if (!checks.reserveRateLimited) errors.push('reserve attempts are not rate limited')
  if (!checks.pendingConnectsBounded) errors.push('pending connect queue is unbounded')
  if (!checks.perCircuitRateCapped) {
    warnings.push('per-circuit 1 MiB/s rate cap is not enforced; only byte/session caps are modeled')
  }

  return { checks, errors, warnings }
}

function evaluateSecurityChecks (runtime) {
  const checks = {
    reserveAuthBindsRemoteKey: runtime.reserveAuthBindsRemoteKey,
    connectAuthBindsRemoteKey: runtime.connectAuthBindsRemoteKey,
    endpointOnlyData: runtime.endpointOnlyData,
    closeOnFrameTooLarge: runtime.closeOnFrameTooLarge,
    closeOnByteCap: runtime.closeOnByteCap,
    silentDropUnknownCircuit: runtime.silentDropUnknownCircuit
  }
  const errors = []
  const warnings = []

  for (const [name, valid] of Object.entries(checks)) {
    if (valid !== true) errors.push('missing circuit security check: ' + name)
  }

  return { checks, errors, warnings }
}

function evaluateChannelWarnings (channels) {
  const warnings = []
  if (!channels.kernel && channels.hiverelayCompat) {
    warnings.push('using HiveRelay compatibility channel until rk-circuit is introduced')
  }
  if (!channels.kernel && !channels.hivemeshT1 && !channels.hiverelayCompat) {
    warnings.push('no recognized circuit channel advertised')
  }
  return warnings
}

function evaluateDecisions (decisions, context) {
  return (Array.isArray(decisions) ? decisions : [])
    .map(decision => evaluateDecision(decision, context))
    .sort((a, b) => a.id.localeCompare(b.id))
}

function evaluateDecision (decision = {}, { limits, runtime, channels }) {
  const type = typeof decision.type === 'string' ? decision.type : 'unknown'
  const expectedAccepted = decision.expectedAccepted === true
  let accepted = false
  let reason = 'unsupported-decision'

  if (type === 'open-channel') {
    const verdict = canOpenChannel(decision, channels)
    accepted = verdict.accepted
    reason = verdict.reason
  } else if (type === 'reserve') {
    accepted = decision.remoteKeyMatches === true && runtime.reserveAuthBindsRemoteKey === true
    reason = accepted ? null : 'E_KEY_ROLE'
  } else if (type === 'connect') {
    accepted = decision.remoteKeyMatches === true && runtime.connectAuthBindsRemoteKey === true
    reason = accepted ? null : 'E_KEY_ROLE'
  } else if (type === 'circuit-count') {
    accepted = safeInteger(decision.activeCircuitsForPeer) < limits.maxCircuitsPerPeer
    reason = accepted ? null : 'E_CIRCUIT_LIMIT'
  } else if (type === 'frame') {
    accepted = safeInteger(decision.bytes) <= limits.maxFrameBytes
    reason = accepted ? null : 'E_CIRCUIT_LIMIT'
  } else if (type === 'session-bytes') {
    accepted = safeInteger(decision.bytesRelayed) + safeInteger(decision.nextBytes) <= limits.maxBytes
    reason = accepted ? null : 'E_CIRCUIT_LIMIT'
  } else if (type === 'session-duration') {
    accepted = safeInteger(decision.durationMs) <= effectiveDurationCap(limits, runtime)
    reason = accepted ? null : 'E_CIRCUIT_LIMIT'
  } else if (type === 'byte-rate') {
    accepted = !Number.isSafeInteger(limits.rateCapBytesPerSecond) ||
      safeInteger(decision.bytesPerSecond) <= limits.rateCapBytesPerSecond
    reason = accepted ? null : 'E_CIRCUIT_LIMIT'
  } else if (type === 'unknown-circuit-data') {
    accepted = runtime.silentDropUnknownCircuit === true
    reason = accepted ? 'DROP_SILENT' : 'E_CIRCUIT_UNKNOWN'
  }

  return {
    id: typeof decision.id === 'string' ? decision.id : type,
    type,
    accepted,
    expectedAccepted,
    reason,
    matchesExpectation: accepted === expectedAccepted
  }
}

function canOpenChannel (decision, channels) {
  const channel = typeof decision.channel === 'string' ? decision.channel : null
  const rolePrefix = typeof decision.rolePrefix === 'string' ? decision.rolePrefix : null
  if (channel === RELAYKERNEL_CHANNEL) {
    const accepted = CIRCUIT_CLIENT_ROLES.includes(rolePrefix) || RELAY_SERVER_ROLES.includes(rolePrefix)
    return { accepted, reason: accepted ? null : 'E_KEY_ROLE' }
  }
  if (channel === HIVEMESH_T1_CHANNEL) {
    const accepted = rolePrefix === 'rk1' && channels.hivemeshT1
    return { accepted, reason: accepted ? null : 'E_KEY_TIER' }
  }
  if (channel === HIVERELAY_COMPAT_CHANNEL) {
    const accepted = channels.hiverelayCompat && (CIRCUIT_CLIENT_ROLES.includes(rolePrefix) || RELAY_SERVER_ROLES.includes(rolePrefix))
    return { accepted, reason: accepted ? null : 'E_KEY_ROLE' }
  }
  return { accepted: false, reason: 'E_UNKNOWN_CHANNEL' }
}

function effectiveDurationCap (limits, runtime) {
  if (runtime.relayAccountingEnabled && runtime.relayMaxCircuitDurationMs) {
    return Math.min(limits.maxSessionMs, runtime.relayMaxCircuitDurationMs)
  }
  return limits.maxSessionMs
}

function bool (value, fallback) {
  return typeof value === 'boolean' ? value : fallback
}

function positiveInteger (value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

function safeInteger (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function orderedUnique (values) {
  const out = []
  const seen = new Set()
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0 || seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}
