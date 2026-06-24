import { isValidHexKey } from '../constants.js'

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

export async function runOperatorCustodyAction ({
  action,
  body = {},
  intentId = null,
  node
}) {
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
  node
}) {
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
