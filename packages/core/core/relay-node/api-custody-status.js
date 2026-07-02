import { isValidHexKey } from '../constants.js'
import { custodyDisabledResult } from './api-custody-disabled.js'

const CUSTODY_STATUS_PREFIX = '/api/custody/'
const CUSTODY_STATUS_SUFFIX = '/status'
const CUSTODY_STATUS_DETAILED_AUTH_MESSAGE = 'Unauthorized — API key required for detailed custody status'

export function buildCustodyStatusRoutePayload ({
  path,
  url,
  registry,
  disabled = false
} = {}) {
  if (disabled) return custodyDisabledResult()

  if (!registry) {
    return {
      status: 503,
      payload: { error: 'Registry not running' }
    }
  }

  const intentId = custodyStatusIntentId(path)
  if (!isValidHexKey(intentId, 64)) {
    return {
      status: 400,
      payload: { error: 'intentId must be 64 hex characters' }
    }
  }

  const detailed = isDetailedCustodyStatusQuery(url)
  if (detailed) {
    return {
      requiresAuth: true,
      authMessage: CUSTODY_STATUS_DETAILED_AUTH_MESSAGE,
      intentId,
      payload: buildCustodyStatusPayload(registry.getCustodyStatus(intentId), { detailed: true })
    }
  }

  return {
    intentId,
    payload: buildCustodyStatusPayload(registry.getCustodyStatus(intentId))
  }
}

export function isCustodyStatusRoute (path) {
  return typeof path === 'string' && path.startsWith(CUSTODY_STATUS_PREFIX) && path.endsWith(CUSTODY_STATUS_SUFFIX)
}

export function resolveCustodyStatusRoute (method, path) {
  if (method !== 'GET') return null
  if (isCustodyStatusRoute(path)) return { kind: 'custody-status' }
  return null
}

export function custodyStatusIntentId (path) {
  return isCustodyStatusRoute(path)
    ? path.slice(CUSTODY_STATUS_PREFIX.length, -CUSTODY_STATUS_SUFFIX.length)
    : ''
}

export function isDetailedCustodyStatusQuery (url) {
  const params = url && url.searchParams
  if (!params || typeof params.get !== 'function') return false
  const detailed = params.get('detailed')
  return detailed === '1' || detailed === 'true'
}

export function buildCustodyStatusPayload (status = {}, opts = {}) {
  return opts.detailed ? detailedCustodyStatus(status) : redactCustodyStatus(status)
}

export function detailedCustodyStatus (status = {}) {
  return {
    ...redactCustodyStatus(status),
    pvss: sanitizePvssSummary(status.pvss),
    commitPendingReason: safeCustodyString(status.commitPendingReason),
    sourceRetirementPendingReason: safeCustodyString(status.sourceRetirementPendingReason),
    sourceRetired: status.sourceRetired === true,
    committed: status.committed === true,
    receipts: Array.isArray(status.receipts)
      ? status.receipts.map(detailedCustodyReceipt)
      : []
  }
}

export function redactCustodyStatus (status = {}) {
  return {
    intentId: status.intentId || null,
    blindContentId: status.blindContentId || null,
    custodyMode: status.custodyMode || 'blind',
    requiredReplicas: status.requiredReplicas || 0,
    receiptCount: status.receiptCount || 0,
    quorumReached: status.quorumReached === true,
    receiptRoot: status.receiptRoot || null,
    relayQuorum: Array.isArray(status.relayQuorum) ? status.relayQuorum : [],
    receipts: Array.isArray(status.receipts)
      ? status.receipts.map(redactCustodyReceipt)
      : [],
    committed: status.committed === true,
    sourceRetired: status.sourceRetired === true,
    proofCount: status.proofCount || 0,
    passingProofs: status.passingProofs || 0,
    nonServingProofCount: status.nonServingProofCount || 0,
    nonServingRelays: Array.isArray(status.nonServingRelays) ? status.nonServingRelays : [],
    expiryWitnessCount: status.expiryWitnessCount || 0,
    validExpiryWitnessCount: status.validExpiryWitnessCount || 0,
    expiryWitnessRelays: Array.isArray(status.expiryWitnessRelays) ? status.expiryWitnessRelays : []
  }
}

export function redactCustodyReceipt (receipt = {}) {
  return {
    relayPubkey: receipt.relayPubkey || null,
    shareIndex: Number.isInteger(receipt.shareIndex) ? receipt.shareIndex : null,
    shareVerified: receipt.shareVerified === true,
    anchored: receipt.anchored === true
  }
}

export function detailedCustodyReceipt (receipt = {}) {
  return {
    ...redactCustodyReceipt(receipt),
    relayRegion: safeCustodyString(receipt.relayRegion),
    receivedAt: safeCustodyTimestamp(receipt.receivedAt),
    attestedAt: safeCustodyTimestamp(receipt.attestedAt)
  }
}

function sanitizePvssSummary (pvss) {
  if (!pvss || typeof pvss !== 'object' || Array.isArray(pvss)) return null
  return {
    shareScheme: safeCustodyString(pvss.shareScheme),
    shareThreshold: safeCustodyCount(pvss.shareThreshold),
    commitmentRoot: safeHex(pvss.commitmentRoot, 64),
    shareIndices: Array.isArray(pvss.shareIndices)
      ? pvss.shareIndices.filter(Number.isSafeInteger).filter(n => n >= 0).slice(0, 1024)
      : []
  }
}

function safeCustodyCount (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function safeCustodyTimestamp (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function safeHex (value, length) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value)
    ? value.toLowerCase()
    : null
}

function safeCustodyString (value) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || hasControlChar(text)) return null
  return text.length > 256 ? text.slice(0, 256) : text
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}
