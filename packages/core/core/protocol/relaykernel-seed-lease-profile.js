import b4a from 'b4a'
import sodium from 'sodium-universal'

export const RELAYKERNEL_SEED_LEASE_PROFILE_KIND = 'relaykernel-seed-lease-profile'
export const RELAYKERNEL_SEED_LEASE_PROFILE_VERSION = 1
export const RELAYKERNEL_SEED_NONCE_WINDOW_SECONDS = 60 * 60

const GIB = 1024 * 1024 * 1024
const DAY_SECONDS = 24 * 60 * 60
const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_16 = /^[0-9a-f]{32}$/i

export const RELAYKERNEL_SEED_LEASE_DEFAULT_CAPS = Object.freeze({
  maxConcurrentLeases: 256,
  maxStorageCap: 4 * GIB,
  maxRetainHorizonSeconds: 90 * DAY_SECONDS,
  heartbeatIntervalSeconds: 300
})

export const RELAYKERNEL_SEED_LEASE_HARD_CAPS = Object.freeze({
  maxConcurrentLeases: 4096,
  maxStorageCap: 64 * GIB,
  maxRetainHorizonSeconds: 365 * DAY_SECONDS,
  heartbeatIntervalSeconds: 3600
})

export function buildRelayKernelSeedLeaseCaps (opts = {}) {
  return {
    maxConcurrentLeases: cappedInteger(
      opts.maxConcurrentLeases,
      RELAYKERNEL_SEED_LEASE_DEFAULT_CAPS.maxConcurrentLeases,
      RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxConcurrentLeases
    ),
    maxStorageCap: cappedInteger(
      opts.maxStorageCap,
      RELAYKERNEL_SEED_LEASE_DEFAULT_CAPS.maxStorageCap,
      RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxStorageCap
    ),
    maxRetainHorizonSeconds: cappedInteger(
      opts.maxRetainHorizonSeconds,
      RELAYKERNEL_SEED_LEASE_DEFAULT_CAPS.maxRetainHorizonSeconds,
      RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxRetainHorizonSeconds
    ),
    heartbeatIntervalSeconds: cappedInteger(
      opts.heartbeatIntervalSeconds,
      RELAYKERNEL_SEED_LEASE_DEFAULT_CAPS.heartbeatIntervalSeconds,
      RELAYKERNEL_SEED_LEASE_HARD_CAPS.heartbeatIntervalSeconds
    ),
    nonceWindowSeconds: RELAYKERNEL_SEED_NONCE_WINDOW_SECONDS
  }
}

export function evaluateRelayKernelSeedLeaseProfile (input = {}) {
  const now = safeInteger(input.now, Math.floor(Date.now() / 1000))
  const caps = buildRelayKernelSeedLeaseCaps(input.capLimits)
  const nonceSeen = recentNonceSet(input.nonceHistory, now, caps.nonceWindowSeconds)
  const heartbeat = summarizeHeartbeats(input.activeLeases, now, caps)
  let activeLeaseCount = heartbeat.length
  const requests = []

  for (const request of Array.isArray(input.requests) ? input.requests : []) {
    const decision = evaluateSeedRequest(request, {
      now,
      caps,
      nonceSeen,
      activeLeaseCount
    })
    requests.push(decision)
    if (decision.accepted) activeLeaseCount++
  }

  return {
    kind: RELAYKERNEL_SEED_LEASE_PROFILE_KIND,
    version: RELAYKERNEL_SEED_LEASE_PROFILE_VERSION,
    now,
    capLimits: caps,
    activeLeaseCount,
    heartbeat,
    requests
  }
}

function evaluateSeedRequest (request, ctx) {
  const normalized = normalizeSeedRequest(request)
  if (!normalized.ok) return reject(request, 'E_MALFORMED', normalized.reason)
  const seed = normalized.seed
  const nonceKey = seed.publisherPubkey + ':' + seed.nonce
  if (ctx.nonceSeen.has(nonceKey)) {
    return reject(seed, 'E_NONCE_REPLAY', 'nonce already used for publisher in sliding window')
  }

  const horizon = seed.retainUntil - ctx.now
  if (seed.storageCap > RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxStorageCap) {
    return reject(seed, 'E_CAP_EXCEEDED', 'storageCap exceeds hard cap', 'storageCap')
  }
  if (horizon > RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxRetainHorizonSeconds) {
    return reject(seed, 'E_CAP_EXCEEDED', 'retainUntil exceeds hard horizon', 'retainUntil')
  }
  if (horizon > ctx.caps.maxRetainHorizonSeconds) {
    return reject(seed, 'E_CAP_EXCEEDED', 'retainUntil exceeds cap-limits.maxRetainHorizonSeconds', 'retainUntil')
  }
  if (ctx.activeLeaseCount >= ctx.caps.maxConcurrentLeases) {
    return reject(seed, 'E_CAP_EXCEEDED', 'concurrent lease cap reached', 'maxConcurrentLeases')
  }

  ctx.nonceSeen.add(nonceKey)
  const actualCap = Math.min(seed.storageCap, ctx.caps.maxStorageCap)
  const appliedCaps = actualCap < seed.storageCap ? ['storageCap'] : []
  return {
    accepted: true,
    request: seed,
    ack: {
      discoveryKey: seed.discoveryKey,
      leaseId: leaseIdFor(seed),
      acceptedAt: ctx.now,
      actualCap
    },
    appliedCaps
  }
}

function normalizeSeedRequest (request) {
  if (!request || typeof request !== 'object') return { ok: false, reason: 'seed request object required' }
  const seed = {
    discoveryKey: lowerHex(request.discoveryKey, HEX_32),
    publisherPubkey: lowerHex(request.publisherPubkey, HEX_32),
    retainUntil: safeInteger(request.retainUntil, null),
    storageCap: safeInteger(request.storageCap, null),
    proofTier: safeInteger(request.proofTier, null),
    nonce: lowerHex(request.nonce, HEX_16)
  }
  if (!seed.discoveryKey) return { ok: false, reason: 'discoveryKey required' }
  if (!seed.publisherPubkey) return { ok: false, reason: 'publisherPubkey required' }
  if (!Number.isSafeInteger(seed.retainUntil) || seed.retainUntil < 0) return { ok: false, reason: 'retainUntil must be a non-negative integer' }
  if (!Number.isSafeInteger(seed.storageCap) || seed.storageCap < 0) return { ok: false, reason: 'storageCap must be a non-negative integer' }
  if (![0, 1, 2].includes(seed.proofTier)) return { ok: false, reason: 'proofTier must be 0, 1, or 2' }
  if (!seed.nonce) return { ok: false, reason: 'nonce must be 16 bytes hex' }
  return { ok: true, seed }
}

function summarizeHeartbeats (leases, now, caps) {
  return (Array.isArray(leases) ? leases : [])
    .map(lease => {
      const lastHeartbeatAt = safeInteger(lease?.lastHeartbeatAt, null)
      const heartbeatAgeSeconds = Number.isSafeInteger(lastHeartbeatAt)
        ? Math.max(0, now - lastHeartbeatAt)
        : null
      const degraded = heartbeatAgeSeconds !== null && heartbeatAgeSeconds > caps.heartbeatIntervalSeconds
      return {
        leaseId: typeof lease?.leaseId === 'string' ? lease.leaseId : null,
        discoveryKey: lowerHex(lease?.discoveryKey, HEX_32),
        publisherPubkey: lowerHex(lease?.publisherPubkey, HEX_32),
        serving: true,
        degraded,
        heartbeatAgeSeconds,
        reason: degraded ? 'heartbeat-timeout' : null
      }
    })
    .filter(lease => lease.discoveryKey && lease.publisherPubkey)
    .sort((a, b) => a.discoveryKey.localeCompare(b.discoveryKey))
}

function recentNonceSet (history, now, windowSeconds) {
  const seen = new Set()
  for (const item of Array.isArray(history) ? history : []) {
    const publisherPubkey = lowerHex(item?.publisherPubkey, HEX_32)
    const nonce = lowerHex(item?.nonce, HEX_16)
    const seenAt = safeInteger(item?.seenAt, null)
    if (!publisherPubkey || !nonce || !Number.isSafeInteger(seenAt)) continue
    if (seenAt > now || now - seenAt > windowSeconds) continue
    seen.add(publisherPubkey + ':' + nonce)
  }
  return seen
}

function reject (request, code, reason, field = null) {
  return {
    accepted: false,
    request: request && typeof request === 'object' ? normalizeRejectedRequest(request) : null,
    error: { code, reason, field }
  }
}

function normalizeRejectedRequest (request) {
  return {
    discoveryKey: lowerHex(request.discoveryKey, HEX_32),
    publisherPubkey: lowerHex(request.publisherPubkey, HEX_32),
    retainUntil: Number.isSafeInteger(request.retainUntil) ? request.retainUntil : null,
    storageCap: Number.isSafeInteger(request.storageCap) ? request.storageCap : null,
    proofTier: Number.isSafeInteger(request.proofTier) ? request.proofTier : null,
    nonce: lowerHex(request.nonce, HEX_16)
  }
}

function leaseIdFor (seed) {
  const out = b4a.alloc(16)
  sodium.crypto_generichash(
    out,
    b4a.from(JSON.stringify([
      'relaykernel-seed-lease-id-v1',
      seed.publisherPubkey,
      seed.discoveryKey,
      seed.nonce
    ]))
  )
  return b4a.toString(out, 'hex')
}

function cappedInteger (value, fallback, hardCap) {
  const n = Number.isSafeInteger(value) && value > 0 ? value : fallback
  return Math.min(n, hardCap)
}

function safeInteger (value, fallback) {
  return Number.isSafeInteger(value) ? value : fallback
}

function lowerHex (value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) return null
  return value.toLowerCase()
}
