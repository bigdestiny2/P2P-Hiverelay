import { isValidHexKey } from '../constants.js'

function count (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER)
}

function timestampOrNull (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return null
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER)
}

export function isDetailedAnchorStatusQuery (value) {
  return value === '1' || value === 'true'
}

export async function buildAnchorProofPayload ({
  node,
  appKey
} = {}) {
  if (!isValidHexKey(appKey)) {
    return {
      ok: false,
      status: 400,
      payload: { error: 'invalid appKey' }
    }
  }

  if (!node || typeof node.createAnchorProof !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'proof generation failed' }
    }
  }

  try {
    return {
      ok: true,
      status: 200,
      payload: await node.createAnchorProof(appKey)
    }
  } catch (err) {
    const message = err && err.message ? err.message : String(err || 'proof generation failed')
    const status = /invalid appKey/.test(message) ? 400 : 503
    return {
      ok: false,
      status,
      payload: { error: message || 'proof generation failed' }
    }
  }
}

export function buildAnchorStatusPayload ({
  appRegistry,
  detailed = false,
  lastCheckedAt = null
} = {}) {
  if (!appRegistry || typeof appRegistry.anchorStats !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'anchor stats unavailable' }
    }
  }

  const stats = appRegistry.anchorStats()
  const entries = detailed
    ? anchorStatusEntries(appRegistry)
    : null

  return {
    ok: true,
    status: 200,
    payload: {
      total: count(stats && stats.total),
      anchored: count(stats && stats.anchored),
      unanchored: count(stats && stats.unanchored),
      neverChecked: count(stats && stats.neverChecked),
      lastCheckedAt: timestampOrNull(lastCheckedAt),
      entries
    }
  }
}

export function anchorStatusEntries (appRegistry) {
  if (!appRegistry || typeof appRegistry.catalog !== 'function') return []
  return appRegistry.catalog().map(anchorStatusEntry)
}

export function anchorStatusEntry (entry = {}) {
  return {
    appKey: entry.appKey,
    type: entry.type,
    anchored: entry.anchored,
    anchoredAt: entry.anchoredAt,
    anchoredLength: entry.anchoredLength,
    custodyIntentId: entry.custodyIntentId || null,
    blind: entry.blind === true,
    storageClass: entry.storageClass || null,
    availabilityClass: entry.availabilityClass || null
  }
}
