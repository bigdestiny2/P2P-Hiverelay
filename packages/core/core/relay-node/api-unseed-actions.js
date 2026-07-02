import { isValidHexKey } from '../constants.js'

export const OPERATOR_UNSEED_AUTH_MESSAGE = 'Unauthorized — API key required for /unseed (use /api/v1/unseed for developer-signed unseed)'

function errorPayload (message) {
  return { error: message }
}

function badRequest (message) {
  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(message) }
}

function unavailable (message) {
  return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload(message) }
}

function validateAppKey (body) {
  if (!body.appKey) return badRequest('appKey required')
  if (!isValidHexKey(body.appKey, 64)) return badRequest('appKey must be 64 hex characters')
  return null
}

function validateSignedUnseedBody (body) {
  const appKeyProblem = validateAppKey(body)
  if (appKeyProblem) return appKeyProblem

  if (!body.publisherPubkey) return badRequest('publisherPubkey required')
  if (!isValidHexKey(body.publisherPubkey, 64)) return badRequest('publisherPubkey must be 64 hex characters')
  if (!body.signature) return badRequest('signature required')
  if (!isValidHexKey(body.signature, 128)) return badRequest('signature must be 128 hex characters')
  if (body.timestamp === undefined || body.timestamp === null) return badRequest('timestamp required (unix ms)')
  if (!Number.isSafeInteger(body.timestamp) || body.timestamp <= 0) {
    return badRequest('timestamp must be a positive safe integer')
  }
  return null
}

export function resolveUnseedRoute (method, path) {
  if (method !== 'POST') return null
  if (path === '/unseed') {
    return {
      kind: 'operator-unseed',
      authMessage: OPERATOR_UNSEED_AUTH_MESSAGE
    }
  }
  if (path === '/api/v1/unseed') return { kind: 'publisher-unseed' }
  return null
}

export async function runOperatorUnseedAction ({
  body = {},
  node
}) {
  body = body || {}
  const appKeyProblem = validateAppKey(body)
  if (appKeyProblem) return appKeyProblem
  if (!node || typeof node.unseedApp !== 'function') return unavailable('unseedApp not available')

  await node.unseedApp(body.appKey)
  return { ok: true, payload: { ok: true } }
}

export async function runPublisherUnseedAction ({
  body = {},
  node
}) {
  body = body || {}
  const bodyProblem = validateSignedUnseedBody(body)
  if (bodyProblem) return bodyProblem
  if (!node || typeof node.verifyUnseedRequest !== 'function' || typeof node.unseedApp !== 'function') {
    return unavailable('publisher unseed not available')
  }

  const result = node.verifyUnseedRequest(body.appKey, body.publisherPubkey, body.signature, body.timestamp)
  if (!result.ok) return { ok: false, kind: 'forbidden', status: 403, payload: errorPayload(result.error) }

  await node.unseedApp(body.appKey)

  if (typeof node.broadcastUnseed === 'function') {
    node.broadcastUnseed(body.appKey, body.publisherPubkey, body.signature, body.timestamp)
  }

  return {
    ok: true,
    payload: { ok: true, message: 'App unseeded and unseed broadcast to network' }
  }
}
