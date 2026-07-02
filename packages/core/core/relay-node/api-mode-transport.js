import { validatePositiveInt, validatePositiveNumber } from './api-validation.js'

export const AVAILABLE_MODES = [
  'relay-core',
  'relaykernel',
  'custody-relay',
  'public',
  'standard',
  'private',
  'hybrid',
  'homehive',
  'seed-only',
  'relay-only',
  'stealth',
  'gateway',
  'service-operator',
  'experimental-lab'
]

const TRANSPORT_NAME_PATTERN = /^[a-z0-9-]+$/
const RESERVED_TRANSPORT_NAMES = new Set(['__proto__', 'constructor', 'prototype'])
const MODE_TRANSPORT_MANAGEMENT_ROUTES = Object.freeze({
  'POST /api/manage/mode': Object.freeze({ kind: 'mode-switch' }),
  'POST /api/manage/transport': Object.freeze({ kind: 'transport-toggle' })
})

export function resolveModeTransportManagementRoute (method, path) {
  const route = MODE_TRANSPORT_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function errorPayload (message, extra = null) {
  return extra ? { error: message, ...extra } : { error: message }
}

function objectRecord (value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function validateBooleanField (value, field) {
  if (typeof value !== 'boolean') return { ok: false, payload: errorPayload(`${field} must be a boolean`) }
  return { ok: true, value }
}

function emitRollbackError (emit, error) {
  if (typeof emit !== 'function') return
  emit('config-rollback-error', {
    message: error && error.message ? error.message : String(error || 'unknown error'),
    error
  })
}

function modeNote (mode) {
  if (mode === 'stealth') return 'Enable Tor transport for full stealth mode'
  if (mode === 'homehive') return 'HomeHive mode active — low resource, LAN-priority'
  if (mode === 'custody-relay') return 'Custody relay mode active — blind atomic handoff focused'
  if (mode === 'relay-core') return 'Relay Core active — focused availability/custody kernel'
  if (mode === 'relaykernel') return 'RelayKernel profile active — seed/proof/circuit/meta/accounting only'
  return null
}

function buildModeOverrides (body = {}) {
  const overrides = {}

  if (body.maxConnections !== undefined) {
    const result = validatePositiveInt(body.maxConnections, 0, 100000, 'maxConnections')
    if (!result.ok) return { ok: false, payload: errorPayload(result.error) }
    overrides.maxConnections = result.value
  }

  if (body.maxRelayBandwidthMbps !== undefined) {
    const result = validatePositiveNumber(body.maxRelayBandwidthMbps, 0, 100000, 'maxRelayBandwidthMbps')
    if (!result.ok) return { ok: false, payload: errorPayload(result.error) }
    overrides.maxRelayBandwidthMbps = result.value
  }

  if (body.maxStorageBytes !== undefined) {
    const result = validatePositiveInt(body.maxStorageBytes, 0, 10e12, 'maxStorageBytes')
    if (!result.ok) return { ok: false, payload: errorPayload(result.error) }
    overrides.maxStorageBytes = result.value
  }

  for (const field of ['discovery', 'access', 'pairing']) {
    if (body[field] !== undefined) {
      if (!objectRecord(body[field])) return { ok: false, payload: errorPayload(`${field} must be an object`) }
      overrides[field] = body[field]
    }
  }
  if (body.registryAutoAccept !== undefined) {
    const result = validateBooleanField(body.registryAutoAccept, 'registryAutoAccept')
    if (!result.ok) return result
    overrides.registryAutoAccept = result.value
  }

  return { ok: true, overrides }
}

export async function runModeSwitchAction ({
  body,
  node,
  persistConfig = async () => {},
  emit = null
}) {
  const { mode } = body || {}
  if (!mode) {
    return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('mode required') }
  }

  if (!AVAILABLE_MODES.includes(mode)) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: errorPayload('Unknown mode: ' + mode, { available: AVAILABLE_MODES })
    }
  }

  const built = buildModeOverrides(body)
  if (!built.ok) {
    return { ok: false, kind: 'bad-request', status: 400, payload: built.payload }
  }

  const previousConfig = node.config
  const previousMode = node.mode
  const previousOperatingMode = node._operatingMode
  try {
    await node.applyMode(mode, built.overrides)
  } catch (err) {
    return {
      ok: false,
      kind: 'apply-mode',
      status: 400,
      payload: errorPayload(err.message || 'Failed to apply mode')
    }
  }

  try {
    await persistConfig()
  } catch (err) {
    node.config = previousConfig
    node.mode = previousMode
    node._operatingMode = previousOperatingMode
    if (node.running && typeof node._syncAccessControl === 'function') {
      try {
        await node._syncAccessControl()
      } catch (rollbackErr) {
        emitRollbackError(emit, rollbackErr)
      }
    }
    return { ok: false, kind: 'config-persist', error: err }
  }

  return {
    ok: true,
    payload: {
      ok: true,
      mode,
      applied: ['mode'],
      note: modeNote(mode)
    }
  }
}

export async function runTransportToggleAction ({
  body,
  config,
  persistConfig = async () => {}
}) {
  const { transport, enabled } = body || {}
  if (!transport || typeof transport !== 'string') {
    return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('transport required') }
  }

  if (RESERVED_TRANSPORT_NAMES.has(transport) || !TRANSPORT_NAME_PATTERN.test(transport)) {
    return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Invalid transport name') }
  }

  if (enabled !== undefined) {
    const result = validateBooleanField(enabled, 'enabled')
    if (!result.ok) return { ok: false, kind: 'bad-request', status: 400, payload: result.payload }
  }

  const hadTransports = Object.prototype.hasOwnProperty.call(config, 'transports')
  const previousTransports = config.transports && typeof config.transports === 'object'
    ? { ...config.transports }
    : config.transports
  if (!config.transports) config.transports = { udp: true }

  config.transports[transport] = enabled !== false

  try {
    await persistConfig()
  } catch (err) {
    if (!hadTransports) {
      delete config.transports
    } else {
      config.transports = previousTransports
    }
    return { ok: false, kind: 'config-persist', error: err }
  }

  return {
    ok: true,
    payload: {
      ok: true,
      transport,
      enabled: config.transports[transport],
      note: 'Transport changes may require a node restart to take full effect'
    }
  }
}

export async function runModeTransportManagementRouteAction ({
  route,
  body = {},
  node,
  config,
  persistConfig = async () => {},
  emit = null
} = {}) {
  if (!route) {
    return { ok: false, kind: 'not-found', status: 404, payload: errorPayload('unknown mode/transport management route') }
  }

  if (route.kind === 'mode-switch') {
    return runModeSwitchAction({ body, node, persistConfig, emit })
  }

  if (route.kind === 'transport-toggle') {
    return runTransportToggleAction({ body, config, persistConfig })
  }

  return { ok: false, kind: 'not-found', status: 404, payload: errorPayload('unknown mode/transport management route') }
}
