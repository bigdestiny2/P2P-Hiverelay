import { isValidHexKey } from '../constants.js'
import { custodyDisabledResult } from './api-custody-disabled.js'

const OPERATOR_CUSTODY_PREFIX = '/api/custody/'
const PUBLISHER_CUSTODY_PREFIX = '/api/v1/custody/'

function errorPayload (message) {
  return { error: message }
}

function errorMessage (err, fallback = null) {
  if (err && err.message) return err.message
  if (fallback) return fallback
  return String(err || 'unknown error')
}

function invalidIntentId () {
  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('intentId must be 64 hex characters') }
}

function registryNotRunning (message = 'Registry not running') {
  return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload(message) }
}

function validateIntentId (intentId) {
  return isValidHexKey(intentId, 64)
}

function keyPairFromNode (node) {
  return node && node.swarm ? node.swarm.keyPair : null
}

function prefixedActionRoute ({ path, prefix, suffix, action, authMessage = null }) {
  if (typeof path !== 'string' || !path.startsWith(prefix) || !path.endsWith(suffix)) return null
  return {
    action,
    intentId: path.slice(prefix.length, -suffix.length),
    authMessage
  }
}

async function runRegistryCall ({ call, providerErrorFallback = null, wrapOk = true }) {
  try {
    const entry = await call()
    return { ok: true, payload: wrapOk ? { ok: true, ...entry } : entry }
  } catch (err) {
    return {
      ok: false,
      kind: 'provider-error',
      status: 400,
      payload: errorPayload(errorMessage(err, providerErrorFallback))
    }
  }
}

export function resolveOperatorCustodyRoute (method, path) {
  if (method !== 'POST') return null

  if (path === '/api/custody/intent') {
    return {
      action: 'intent',
      intentId: null,
      authMessage: 'Unauthorized — API key required for /api/custody/intent'
    }
  }

  if (path === '/api/custody/proof') {
    return {
      action: 'proof',
      intentId: null,
      authMessage: 'Unauthorized — API key required for /api/custody/proof'
    }
  }

  return prefixedActionRoute({
    path,
    prefix: OPERATOR_CUSTODY_PREFIX,
    suffix: '/commit',
    action: 'commit',
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/commit'
  }) || prefixedActionRoute({
    path,
    prefix: OPERATOR_CUSTODY_PREFIX,
    suffix: '/source-retired',
    action: 'source-retired',
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/source-retired'
  }) || prefixedActionRoute({
    path,
    prefix: OPERATOR_CUSTODY_PREFIX,
    suffix: '/witness',
    action: 'witness',
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/witness'
  }) || prefixedActionRoute({
    path,
    prefix: OPERATOR_CUSTODY_PREFIX,
    suffix: '/non-serving-proof',
    action: 'non-serving-proof',
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/non-serving-proof'
  })
}

export function resolvePublisherCustodyRoute (method, path) {
  if (method !== 'POST') return null

  if (path === '/api/v1/custody/intent') {
    return {
      action: 'intent',
      intentId: null
    }
  }

  return prefixedActionRoute({
    path,
    prefix: PUBLISHER_CUSTODY_PREFIX,
    suffix: '/commit',
    action: 'commit'
  }) || prefixedActionRoute({
    path,
    prefix: PUBLISHER_CUSTODY_PREFIX,
    suffix: '/source-retired',
    action: 'source-retired'
  })
}

export async function runOperatorCustodyAction ({
  action,
  body = {},
  intentId = null,
  node,
  disabled = false
}) {
  if (disabled) return custodyDisabledResult()

  body = body || {}

  if (action === 'intent') {
    if (!node || !node.seedingRegistry) return registryNotRunning()
    if (!keyPairFromNode(node) && !body.signature) {
      return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Relay keypair unavailable') }
    }
    return runRegistryCall({
      call: () => node.seedingRegistry.publishCustodyIntent(body, keyPairFromNode(node))
    })
  }

  if (action === 'commit') {
    if (!node || !node.seedingRegistry) return registryNotRunning()
    if (!validateIntentId(intentId)) return invalidIntentId()
    return runRegistryCall({
      call: () => node.seedingRegistry.publishCustodyCommit({ ...body, intentId }, keyPairFromNode(node))
    })
  }

  if (action === 'source-retired') {
    if (!node || !node.seedingRegistry) return registryNotRunning()
    if (!validateIntentId(intentId)) return invalidIntentId()
    return runRegistryCall({
      call: () => node.seedingRegistry.publishSourceRetired({ ...body, intentId }, keyPairFromNode(node))
    })
  }

  if (action === 'proof') {
    if (!node || !node.seedingRegistry) return registryNotRunning()
    return runRegistryCall({
      call: () => node.seedingRegistry.recordCustodyProof(body, keyPairFromNode(node))
    })
  }

  if (action === 'witness') {
    if (!validateIntentId(intentId)) return invalidIntentId()
    if (!node || !node.seedingRegistry) return registryNotRunning('registry not running')
    return runRegistryCall({
      call: () => node.seedingRegistry.recordCustodyExpiryWitness({ ...body, intentId }, keyPairFromNode(node)),
      providerErrorFallback: 'witness rejected',
      wrapOk: false
    })
  }

  if (action === 'non-serving-proof') {
    if (!validateIntentId(intentId)) return invalidIntentId()
    try {
      const entry = await node.createCustodyNonServingProof(intentId, body || {})
      return { ok: true, payload: { ok: true, ...entry } }
    } catch (err) {
      const message = errorMessage(err)
      return {
        ok: false,
        kind: 'provider-error',
        status: message.startsWith('STILL_SERVING') ? 409 : 400,
        payload: errorPayload(message)
      }
    }
  }

  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Unknown custody action') }
}

export async function runPublisherCustodyAction ({
  action,
  body = {},
  intentId = null,
  node,
  disabled = false
}) {
  if (disabled) return custodyDisabledResult()

  body = body || {}
  if (!node || !node.seedingRegistry) return registryNotRunning()

  if (action === 'intent') {
    if (!body.signature) {
      return {
        ok: false,
        kind: 'bad-request',
        status: 400,
        payload: errorPayload('signature required (entry must be publisher-signed; see custody-signing.createCustodyIntent)')
      }
    }
    try {
      const entry = await node.seedingRegistry.publishCustodyIntent(body, null)
      return { ok: true, payload: { ok: true, ...entry } }
    } catch (err) {
      return { ok: false, kind: 'custody-error', error: err }
    }
  }

  if (action === 'commit' || action === 'source-retired') {
    if (!validateIntentId(intentId)) return invalidIntentId()
    if (!body.signature) {
      return {
        ok: false,
        kind: 'bad-request',
        status: 400,
        payload: errorPayload('signature required (entry must be publisher-signed)')
      }
    }
    try {
      const entry = action === 'commit'
        ? await node.seedingRegistry.publishCustodyCommit({ ...body, intentId }, null)
        : await node.seedingRegistry.publishSourceRetired({ ...body, intentId }, null)
      return { ok: true, payload: { ok: true, ...entry } }
    } catch (err) {
      return { ok: false, kind: 'custody-error', error: err }
    }
  }

  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Unknown custody action') }
}

export async function runOperatorCustodyRouteAction ({
  route,
  body = {},
  node,
  disabled = false
} = {}) {
  if (!route || !route.action) {
    return { ok: false, kind: 'bad-request', status: 404, payload: errorPayload('unknown operator custody route') }
  }
  return runOperatorCustodyAction({
    action: route.action,
    body,
    intentId: route.intentId,
    node,
    disabled
  })
}

export async function runPublisherCustodyRouteAction ({
  route,
  body = {},
  node,
  disabled = false
} = {}) {
  if (!route || !route.action) {
    return { ok: false, kind: 'bad-request', status: 404, payload: errorPayload('unknown publisher custody route') }
  }
  return runPublisherCustodyAction({
    action: route.action,
    body,
    intentId: route.intentId,
    node,
    disabled
  })
}
