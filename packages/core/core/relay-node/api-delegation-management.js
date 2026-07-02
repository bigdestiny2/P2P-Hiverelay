import { isValidHexKey } from '../constants.js'

export const MAX_DELEGATION_REVOCATION_LIST_ENTRIES = 1000

const DELEGATION_MANAGEMENT_ROUTES = Object.freeze({
  'GET /api/manage/delegation/revocations': Object.freeze({ kind: 'list' }),
  'POST /api/manage/delegation/revoke': Object.freeze({ kind: 'revoke' })
})

function errorPayload (message) {
  return { error: message }
}

function objectRecord (value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function hasOwn (obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function validateCertExpiresAt (body) {
  if (!hasOwn(body, 'certExpiresAt')) return { ok: true, opts: {} }
  if (!Number.isSafeInteger(body.certExpiresAt) || body.certExpiresAt <= 0) {
    return {
      ok: false,
      status: 400,
      payload: errorPayload('certExpiresAt must be a positive safe integer')
    }
  }
  return { ok: true, opts: { certExpiresAt: body.certExpiresAt } }
}

export function resolveDelegationManagementRoute (method, path) {
  const route = DELEGATION_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return {
    ...route,
    authMessage: `Unauthorized — API key required for ${path}`
  }
}

export function buildDelegationRevocationsPayload ({
  listRevocations = null,
  maxEntries = MAX_DELEGATION_REVOCATION_LIST_ENTRIES
} = {}) {
  const raw = typeof listRevocations === 'function' ? listRevocations() : []
  const source = Array.isArray(raw) ? raw : []
  const limit = Number.isSafeInteger(maxEntries) && maxEntries >= 0
    ? maxEntries
    : MAX_DELEGATION_REVOCATION_LIST_ENTRIES
  const revocations = []

  for (const entry of source) {
    if (revocations.length >= limit) break
    const clean = sanitizeRevocationEntry(entry)
    if (clean) revocations.push(clean)
  }

  return {
    count: revocations.length,
    total: source.length,
    truncated: revocations.length < source.length,
    revocations
  }
}

export function buildDelegationRevocationsRoutePayload ({
  route,
  listRevocations = null,
  maxEntries = MAX_DELEGATION_REVOCATION_LIST_ENTRIES
} = {}) {
  if (!route || route.kind !== 'list') {
    return {
      ok: false,
      status: 404,
      payload: errorPayload('unknown delegation revocation route')
    }
  }

  return {
    ok: true,
    payload: buildDelegationRevocationsPayload({ listRevocations, maxEntries })
  }
}

export function runDelegationRevokeAction ({
  body = {},
  node
} = {}) {
  body = body || {}
  if (!node || typeof node.submitRevocation !== 'function') {
    return { ok: false, status: 503, payload: errorPayload('Delegation revocation not available') }
  }
  if (!objectRecord(body.revocation)) {
    return {
      ok: false,
      status: 400,
      payload: errorPayload('revocation required (signed message from primary identity)')
    }
  }

  const expiry = validateCertExpiresAt(body)
  if (!expiry.ok) return { ok: false, status: expiry.status, payload: expiry.payload }

  const result = node.submitRevocation(body.revocation, expiry.opts)
  if (!result || result.ok !== true) {
    return {
      ok: false,
      status: 400,
      payload: errorPayload((result && result.reason) || 'invalid revocation')
    }
  }
  return {
    ok: true,
    payload: {
      ok: true,
      revokedCertSignature: typeof result.revokedCertSignature === 'string' ? result.revokedCertSignature : null
    }
  }
}

function sanitizeRevocationEntry (entry) {
  if (!objectRecord(entry)) return null
  const out = {}
  if (isValidHexKey(entry.revokedCertSignature, 128)) {
    out.revokedCertSignature = entry.revokedCertSignature.toLowerCase()
  }
  if (Number.isSafeInteger(entry.revokedAt) && entry.revokedAt >= 0) out.revokedAt = entry.revokedAt
  if (Number.isSafeInteger(entry.expiresAt) && entry.expiresAt >= 0) out.expiresAt = entry.expiresAt
  if (isValidHexKey(entry.primaryPubkey, 64)) out.primaryPubkey = entry.primaryPubkey.toLowerCase()
  if (typeof entry.reason === 'string' && Buffer.byteLength(entry.reason, 'utf8') <= 256) {
    out.reason = entry.reason
  }
  return Object.keys(out).length > 0 ? out : null
}
