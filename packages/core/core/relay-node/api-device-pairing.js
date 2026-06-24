import { isValidHexKey } from '../constants.js'
import { validatePositiveInt } from './api-validation.js'

export const DEVICE_NAME_MAX_LENGTH = 80
export const MAX_DEVICE_LIST_ENTRIES = 128

function errorPayload (message) {
  return { error: message }
}

function errorMessage (err) {
  return err && err.message ? err.message : String(err || 'unknown error')
}

function isKnownDeviceOperatorError (message) {
  return message === 'Device not in allowlist' || message.startsWith('Maximum devices reached')
}

export function normalizeDeviceName (name) {
  if (name === undefined || name === null || name === '') return { ok: true, value: 'manual' }
  if (typeof name !== 'string') return { ok: false, error: 'name must be a string' }
  const value = name.trim() || 'manual'
  if (value.length > DEVICE_NAME_MAX_LENGTH) {
    return { ok: false, error: `name exceeds max length (${DEVICE_NAME_MAX_LENGTH})` }
  }
  if (hasControlChar(value)) {
    return { ok: false, error: 'name must not contain control characters' }
  }
  return { ok: true, value }
}

export function sanitizeDeviceList (devices) {
  const source = Array.isArray(devices) ? devices : []
  const out = []
  for (const entry of source) {
    if (out.length >= MAX_DEVICE_LIST_ENTRIES) break
    const clean = sanitizeDeviceEntry(entry)
    if (clean) out.push(clean)
  }
  return out
}

export function sanitizeDeviceEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  if (!entry.pubkey || !isValidHexKey(entry.pubkey, 64)) return null
  const name = normalizeDeviceName(entry.name)
  return {
    pubkey: String(entry.pubkey).toLowerCase(),
    name: name.ok ? name.value : 'manual',
    pairedAt: safeTimestamp(entry.pairedAt),
    lastSeen: safeTimestamp(entry.lastSeen)
  }
}

function safeTimestamp (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

export async function runDeviceManagementAction ({
  body = {},
  node
}) {
  body = body || {}

  if (!node.accessControl) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: {
        error: 'Access control is not active in current mode',
        mode: node.mode
      }
    }
  }

  const action = body.action || 'list'
  if (action === 'list') {
    const source = node.listDevices()
    const devices = sanitizeDeviceList(source)
    return {
      ok: true,
      payload: {
        ok: true,
        count: devices.length,
        total: Array.isArray(source) ? source.length : devices.length,
        truncated: Array.isArray(source) && source.length > devices.length,
        devices
      }
    }
  }

  if (action === 'add') {
    if (!body.pubkey || !isValidHexKey(body.pubkey, 64)) {
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('pubkey must be 64 hex characters') }
    }
    const name = normalizeDeviceName(body.name)
    if (!name.ok) return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(name.error) }

    const pubkey = body.pubkey.toLowerCase()
    try {
      await node.addDevice(pubkey, name.value)
    } catch (err) {
      const message = errorMessage(err)
      if (isKnownDeviceOperatorError(message)) {
        return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(message) }
      }
      return { ok: false, kind: 'device-persist', error: err }
    }

    return { ok: true, payload: { ok: true, action: 'added', pubkey, name: name.value } }
  }

  if (action === 'remove') {
    if (!body.pubkey || !isValidHexKey(body.pubkey, 64)) {
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('pubkey must be 64 hex characters') }
    }

    const pubkey = body.pubkey.toLowerCase()
    try {
      await node.removeDevice(pubkey)
    } catch (err) {
      const message = errorMessage(err)
      if (isKnownDeviceOperatorError(message)) {
        return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(message) }
      }
      return { ok: false, kind: 'device-persist', error: err }
    }

    return { ok: true, payload: { ok: true, action: 'removed', pubkey } }
  }

  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Unknown action (use list, add, remove)') }
}

export function runPairingManagementAction ({
  body = {},
  node
}) {
  body = body || {}

  if (!node.accessControl) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: {
        error: 'Pairing is not available in current mode',
        mode: node.mode
      }
    }
  }

  const action = body.action || 'status'
  if (action === 'status') {
    const state = node.accessControl._pairingState
    return {
      ok: true,
      payload: {
        ok: true,
        active: node.accessControl.isPairing,
        expiresAt: state ? state.expiresAt : null
      }
    }
  }

  if (action === 'start') {
    let timeoutMs
    if (body.timeoutMs !== undefined) {
      const result = validatePositiveInt(body.timeoutMs, 10_000, 30 * 60 * 1000, 'timeoutMs')
      if (!result.ok) return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
      timeoutMs = result.value
    }
    const pairing = node.enablePairing({ timeoutMs })
    return {
      ok: true,
      payload: {
        ok: true,
        active: true,
        ...pairing
      }
    }
  }

  if (action === 'stop') {
    node.accessControl.disablePairing()
    return { ok: true, payload: { ok: true, active: false } }
  }

  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Unknown action (use status, start, stop)') }
}
