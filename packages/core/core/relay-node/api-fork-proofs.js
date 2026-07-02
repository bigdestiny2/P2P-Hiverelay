import { isValidHexKey } from '../constants.js'

export const MAX_FORK_PROOF_RECORDS = 200
export const MAX_FORK_PROOF_EVIDENCE_PER_RECORD = 16
export const MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES = 8192

const FORK_PROOF_READ_ROUTES = Object.freeze({
  'GET /api/forks/proofs': Object.freeze({ kind: 'fork-proof-list' })
})

export function resolveForkProofReadRoute (method, path) {
  const route = FORK_PROOF_READ_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function normalizeLimit (value, max) {
  if (!Number.isSafeInteger(value)) return max
  if (value < 0) return 0
  return Math.min(value, max)
}

function hexKeyOrNull (value, length = 64) {
  if (typeof value === 'string' && isValidHexKey(value, length)) return value.toLowerCase()
  if (value && typeof value.length === 'number' && value.length === length / 2) return Buffer.from(value).toString('hex')
  return null
}

function safeString (value, maxBytes) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || Buffer.byteLength(trimmed, 'utf8') > maxBytes) return null
  return trimmed
}

function safeNonNegativeInteger (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function safeTimestamp (value) {
  return Number.isFinite(value) && value >= 0 ? value : null
}

function safeResolution (value) {
  if (value === null) return null
  return value === 'rotated' || value === 'revoked' || value === 'false-alarm'
    ? value
    : null
}

function sanitizeEvidence (evidence, maxBytes) {
  const fromRelay = safeString(evidence && evidence.fromRelay, 128)
  const block = safeString(evidence && evidence.block, maxBytes)
  const signature = safeString(evidence && evidence.signature, maxBytes)
  if (!fromRelay || !block || !signature) return null
  return { fromRelay, block, signature }
}

function sanitizeProofRecord (record, evidenceLimit, evidenceFieldLimit) {
  const hypercoreKey = hexKeyOrNull(record && record.hypercoreKey)
  const blockIndex = safeNonNegativeInteger(record && record.blockIndex)
  const sourceEvidence = Array.isArray(record && record.evidence) ? record.evidence : []
  const evidence = []
  for (const item of sourceEvidence) {
    const clean = sanitizeEvidence(item, evidenceFieldLimit)
    if (!clean) continue
    evidence.push(clean)
    if (evidence.length >= evidenceLimit) break
  }
  if (!hypercoreKey || blockIndex === null || evidence.length < 2) return null

  const out = {
    hypercoreKey,
    blockIndex,
    evidence
  }
  const discoveredAt = safeTimestamp(record && record.discoveredAt)
  if (discoveredAt !== null) out.discoveredAt = discoveredAt
  if (typeof (record && record.operatorAcknowledged) === 'boolean') {
    out.operatorAcknowledged = record.operatorAcknowledged
  }
  const resolution = safeResolution(record && record.resolution)
  if (resolution !== null || (record && record.resolution) === null) out.resolution = resolution
  const resolvedAt = safeTimestamp(record && record.resolvedAt)
  if (resolvedAt !== null) out.resolvedAt = resolvedAt
  if (sourceEvidence.length > evidence.length) out.evidenceTruncated = true
  return out
}

export function buildForkProofsPayload ({
  forkDetector = null,
  maxRecords = MAX_FORK_PROOF_RECORDS,
  maxEvidencePerRecord = MAX_FORK_PROOF_EVIDENCE_PER_RECORD,
  maxEvidenceFieldBytes = MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES
} = {}) {
  const recordLimit = normalizeLimit(maxRecords, MAX_FORK_PROOF_RECORDS)
  const evidenceLimit = normalizeLimit(maxEvidencePerRecord, MAX_FORK_PROOF_EVIDENCE_PER_RECORD)
  const evidenceFieldLimit = normalizeLimit(maxEvidenceFieldBytes, MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES)
  const raw = forkDetector && typeof forkDetector.list === 'function' ? forkDetector.list() : []
  const source = Array.isArray(raw) ? raw : []
  const selected = source.slice(0, recordLimit)
  const proofs = []
  for (const record of selected) {
    const proof = sanitizeProofRecord(record, evidenceLimit, evidenceFieldLimit)
    if (proof) proofs.push(proof)
  }
  return {
    ok: true,
    payload: {
      schemaVersion: 1,
      proofs,
      count: proofs.length,
      total: source.length,
      truncated: source.length > selected.length,
      maxProofs: recordLimit
    },
    headers: { 'Cache-Control': 'public, max-age=30' }
  }
}

export function buildForkProofsRoutePayload ({
  route,
  forkDetector = null,
  maxRecords = MAX_FORK_PROOF_RECORDS,
  maxEvidencePerRecord = MAX_FORK_PROOF_EVIDENCE_PER_RECORD,
  maxEvidenceFieldBytes = MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES
} = {}) {
  if (!route || route.kind !== 'fork-proof-list') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown fork-proof read route' }
    }
  }

  return buildForkProofsPayload({
    forkDetector,
    maxRecords,
    maxEvidencePerRecord,
    maxEvidenceFieldBytes
  })
}
