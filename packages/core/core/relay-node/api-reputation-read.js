import { isValidHexKey } from '../constants.js'

export const MAX_REPUTATION_LEADERBOARD_ENTRIES = 100
export const MAX_REPUTATION_STRING_BYTES = 128

function normalizeLimit (value, max) {
  if (!Number.isSafeInteger(value)) return max
  if (value < 0) return 0
  return Math.min(value, max)
}

function safeFiniteNumber (value, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}

function round2 (value) {
  return Math.round(safeFiniteNumber(value) * 100) / 100
}

function safeNonNegativeNumber (value) {
  const n = safeFiniteNumber(value)
  return n > 0 ? n : 0
}

function safeNonNegativeInteger (value) {
  return Math.floor(safeNonNegativeNumber(value))
}

function safeTimestamp (value) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? n : null
}

function safeString (value, maxBytes = MAX_REPUTATION_STRING_BYTES) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || Buffer.byteLength(trimmed, 'utf8') > maxBytes) return null
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i)
    if (code < 32 || code === 127) return null
  }
  return trimmed
}

function safeRelayId (value) {
  if (typeof value === 'string' && isValidHexKey(value, 64)) return value.toLowerCase()
  if (typeof value !== 'string' && value && typeof value.length === 'number' && value.length === 32) return Buffer.from(value).toString('hex')
  return safeString(value)
}

function safeReliability (value, passedChallenges, totalChallenges) {
  const text = safeString(value, 16)
  if (text === 'N/A') return text
  if (text && /^(?:100|[1-9]?\d)%$/.test(text)) return text
  if (totalChallenges > 0) return Math.round((passedChallenges / totalChallenges) * 100) + '%'
  return 'N/A'
}

export function sanitizeReputationRecord (record, pubkey = null) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null
  const totalChallenges = safeNonNegativeInteger(record.totalChallenges)
  const passedChallenges = Math.min(safeNonNegativeInteger(record.passedChallenges), totalChallenges)
  const failedChallenges = Math.min(
    safeNonNegativeInteger(record.failedChallenges),
    Math.max(0, totalChallenges - passedChallenges)
  )
  const out = {
    score: round2(record.score),
    totalChallenges,
    passedChallenges,
    failedChallenges,
    avgLatencyMs: safeNonNegativeInteger(record.avgLatencyMs),
    totalBytesServed: safeNonNegativeNumber(record.totalBytesServed),
    totalUptimeHours: safeNonNegativeNumber(record.totalUptimeHours),
    region: safeString(record.region, 64),
    geoBonus: record.geoBonus === true,
    firstSeen: safeTimestamp(record.firstSeen),
    lastActivity: safeTimestamp(record.lastActivity)
  }
  if (pubkey) out.pubkey = pubkey
  return out
}

function sanitizeLeaderboardRow (row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null
  const relay = safeRelayId(row.relay)
  if (!relay) return null
  const totalChallenges = safeNonNegativeInteger(row.totalChallenges)
  const passedChallenges = Math.min(safeNonNegativeInteger(row.passedChallenges), totalChallenges)
  const failedChallenges = Math.min(
    safeNonNegativeInteger(row.failedChallenges),
    Math.max(0, totalChallenges - passedChallenges)
  )
  return {
    relay,
    score: round2(row.score),
    reliability: safeReliability(row.reliability, passedChallenges, totalChallenges),
    avgLatencyMs: safeNonNegativeInteger(row.avgLatencyMs),
    uptimeHours: safeNonNegativeInteger(row.uptimeHours),
    bytesServed: safeNonNegativeNumber(row.bytesServed),
    totalChallenges,
    passedChallenges,
    failedChallenges,
    region: safeString(row.region, 64) || 'unknown',
    lastActivity: safeTimestamp(row.lastActivity),
    firstSeen: safeTimestamp(row.firstSeen)
  }
}

export function buildReputationLeaderboardPayload ({
  reputation = null,
  maxEntries = MAX_REPUTATION_LEADERBOARD_ENTRIES
} = {}) {
  const limit = normalizeLimit(maxEntries, MAX_REPUTATION_LEADERBOARD_ENTRIES)
  const raw = reputation && typeof reputation.getLeaderboard === 'function'
    ? reputation.getLeaderboard(limit)
    : []
  const source = Array.isArray(raw) ? raw : []
  const payload = []
  for (const row of source.slice(0, limit)) {
    const clean = sanitizeLeaderboardRow(row)
    if (clean) payload.push(clean)
  }
  return {
    ok: true,
    payload,
    headers: { 'Cache-Control': 'public, max-age=30' }
  }
}

export function buildReputationRecordPayload ({
  reputation = null,
  pubkey = ''
} = {}) {
  if (!isValidHexKey(pubkey, 64)) {
    return { ok: false, status: 400, payload: { error: 'Invalid pubkey' } }
  }
  const key = pubkey.toLowerCase()
  if (!reputation || typeof reputation.getRecord !== 'function') {
    return { ok: true, payload: null, headers: { 'Cache-Control': 'public, max-age=30' } }
  }
  const record = sanitizeReputationRecord(reputation.getRecord(key), key)
  return {
    ok: true,
    payload: record,
    headers: { 'Cache-Control': 'public, max-age=30' }
  }
}
