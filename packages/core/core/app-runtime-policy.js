/**
 * Local App Runtime Policy
 *
 * Guardrail for privileged app bridges such as:
 *
 *   window.hiverelay.services.call(...)
 *
 * The bridge is allowed to put a Hyperdrive app in touch with local Bare/P2P
 * capabilities. It must not become a remote HTTP inference gateway, and it
 * must fail closed when an app has not declared the exact capability it needs.
 */

export const LOCAL_RUNTIME_FEATURE = 'local-app-runtime-v1'
export const LOCAL_RUNTIME_SERVICE_PERMISSION = 'hiverelay.services.call'

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])
const PRIVATE_RUNTIME_PROTOCOLS = new Set([
  'hiverelay-runtime:',
  'pear-runtime:',
  'app-runtime:'
])

const REMOTE_TERMINATING_ROUTES = new Set([
  'http',
  'https',
  'remote-http',
  'relay-http',
  'hosted-http',
  'websocket',
  'ws',
  'wss'
])

const OPAQUE_P2P_ROUTES = new Set([
  'hyperswarm',
  'direct-p2p',
  'circuit-relay',
  'relay-circuit',
  'local-runtime'
])

export function isLoopbackEndpoint (value) {
  if (typeof value !== 'string' || value.trim() === '') return false
  try {
    const url = new URL(value)
    return (url.protocol === 'http:' || url.protocol === 'https:') &&
      LOOPBACK_HOSTS.has(url.hostname)
  } catch {
    return false
  }
}

export function isPrivateRuntimeEndpoint (value) {
  if (typeof value !== 'string' || value.trim() === '') return false
  try {
    const url = new URL(value)
    return PRIVATE_RUNTIME_PROTOCOLS.has(url.protocol)
  } catch {
    return false
  }
}

export function manifestPermissions (manifest = {}) {
  const permissions = new Set()
  addPermissions(permissions, manifest.permissions)
  addPermissions(permissions, manifest.hiverelay?.permissions)
  addPermissions(permissions, manifest.hiverelay?.runtime?.permissions)
  addPermissions(permissions, manifest.runtime?.permissions)
  return permissions
}

export function hasLocalRuntimePermission (manifest = {}, permission = LOCAL_RUNTIME_SERVICE_PERMISSION) {
  return manifestPermissions(manifest).has(permission)
}

/**
 * Pure policy check. It does not dial, fetch, or verify receipts itself.
 *
 * @param {object} req
 * @param {object} req.manifest Hyperdrive app manifest
 * @param {string} req.service Service name, for example "ai"
 * @param {string} req.method Method name, for example "infer"
 * @param {string} [req.route] Transport class. Must be opaque P2P/local runtime.
 * @param {string} [req.endpoint] Optional local private runtime endpoint.
 * @param {boolean} [req.receiptVerification] True when caller will verify locally.
 * @param {object} [opts]
 * @param {boolean} [opts.allowDevLoopbackHttp] Permit loopback HTTP as a dev-only stand-in.
 * @returns {{allowed: boolean, code?: string, reason?: string}}
 */
export function checkLocalRuntimeBridgeCall (req = {}, opts = {}) {
  const manifest = req.manifest || {}
  const service = req.service
  const method = req.method
  const route = req.route || 'local-runtime'
  const endpoint = req.endpoint || null

  if (!hasLocalRuntimePermission(manifest)) {
    return deny('MISSING_PERMISSION', `manifest must declare ${LOCAL_RUNTIME_SERVICE_PERMISSION}`)
  }
  if (!isNonEmptyToken(service)) return deny('BAD_SERVICE', 'service must be a non-empty string')
  if (!isNonEmptyToken(method)) return deny('BAD_METHOD', 'method must be a non-empty string')

  if (REMOTE_TERMINATING_ROUTES.has(route)) {
    return deny('REMOTE_TERMINATING_ROUTE', 'remote HTTP/WebSocket routes may terminate prompts')
  }
  if (!OPAQUE_P2P_ROUTES.has(route)) {
    return deny('UNKNOWN_ROUTE', `unknown local runtime route: ${route}`)
  }

  if (endpoint) {
    const privateEndpoint = isPrivateRuntimeEndpoint(endpoint)
    const devLoopback = opts.allowDevLoopbackHttp === true && isLoopbackEndpoint(endpoint)
    if (!privateEndpoint && !devLoopback) {
      return deny('NON_LOCAL_ENDPOINT', 'endpoint must be a private runtime endpoint')
    }
  }

  if (service === 'ai' && method === 'infer') {
    const privacy = manifest.privacy || {}
    if (privacy.storesPrompts !== false) {
      return deny('PROMPT_PERSISTENCE_UNDECLARED', 'ai.infer apps must declare privacy.storesPrompts=false')
    }
    if (privacy.remoteHttpInference !== 'forbidden' && privacy.remoteHttpInference !== false) {
      return deny('REMOTE_HTTP_NOT_FORBIDDEN', 'ai.infer apps must forbid remote HTTP inference')
    }
    if (req.receiptVerification !== true) {
      return deny('RECEIPT_VERIFICATION_REQUIRED', 'ai.infer calls must verify receipts locally')
    }
  }

  return { allowed: true }
}

export function assertLocalRuntimeBridgeCall (req = {}, opts = {}) {
  const result = checkLocalRuntimeBridgeCall(req, opts)
  if (!result.allowed) {
    const err = new Error(result.reason)
    err.code = result.code
    throw err
  }
  return true
}

function addPermissions (out, permissions) {
  if (!Array.isArray(permissions)) return
  for (const permission of permissions) {
    if (typeof permission === 'string' && permission.trim()) out.add(permission.trim())
  }
}

function isNonEmptyToken (value) {
  return typeof value === 'string' && value.trim() !== ''
}

function deny (code, reason) {
  return { allowed: false, code, reason }
}
