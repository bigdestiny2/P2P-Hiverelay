import { isValidHexKey } from '../constants.js'

export const CATALOG_ACCEPT_MODES = ['open', 'review', 'allowlist', 'closed']

const CATALOG_MANAGEMENT_ROUTES = Object.freeze({
  'POST /registry/auto-accept': Object.freeze({ kind: 'legacy-auto-accept' }),
  'POST /registry/approve': Object.freeze({ kind: 'app', action: 'approve' }),
  'POST /registry/reject': Object.freeze({ kind: 'app', action: 'reject' }),
  'POST /registry/cancel': Object.freeze({ kind: 'cancel' }),
  'POST /api/manage/catalog/mode': Object.freeze({ kind: 'mode' }),
  'POST /api/manage/catalog/allowlist': Object.freeze({ kind: 'allowlist' }),
  'POST /api/manage/catalog/approve': Object.freeze({ kind: 'app', action: 'approve' }),
  'POST /api/manage/catalog/reject': Object.freeze({ kind: 'app', action: 'reject' }),
  'POST /api/manage/catalog/remove': Object.freeze({ kind: 'app', action: 'remove' })
})

const CATALOG_PENDING_ROUTES = Object.freeze({
  'GET /api/registry/pending': Object.freeze({ kind: 'pending-catalog' }),
  'GET /api/manage/catalog/pending': Object.freeze({ kind: 'pending-catalog' })
})

function errorPayload (message) {
  return { error: message }
}

function errorMessage (err) {
  return err && err.message ? err.message : String(err || 'unknown error')
}

function hasOwn (obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function validateBooleanField (value, field) {
  if (typeof value !== 'boolean') return { ok: false, payload: errorPayload(`${field} must be a boolean`) }
  return { ok: true, value }
}

function emitRollbackError (emit, error) {
  if (typeof emit !== 'function') return
  emit('config-rollback-error', {
    message: errorMessage(error),
    error
  })
}

function snapshotAcceptModeConfig (config) {
  return {
    acceptMode: config.acceptMode,
    hadAcceptMode: hasOwn(config, 'acceptMode'),
    registryAutoAccept: config.registryAutoAccept,
    hadRegistryAutoAccept: hasOwn(config, 'registryAutoAccept')
  }
}

function restoreAcceptModeConfig (config, snapshot, emit) {
  try {
    if (snapshot.hadAcceptMode) config.acceptMode = snapshot.acceptMode
    else delete config.acceptMode
    if (snapshot.hadRegistryAutoAccept) config.registryAutoAccept = snapshot.registryAutoAccept
    else delete config.registryAutoAccept
  } catch (err) {
    emitRollbackError(emit, err)
  }
}

function snapshotAllowlistConfig (config) {
  return {
    acceptAllowlist: config.acceptAllowlist,
    hadAcceptAllowlist: hasOwn(config, 'acceptAllowlist')
  }
}

function restoreAllowlistConfig (config, snapshot, emit) {
  try {
    if (snapshot.hadAcceptAllowlist) config.acceptAllowlist = snapshot.acceptAllowlist
    else delete config.acceptAllowlist
  } catch (err) {
    emitRollbackError(emit, err)
  }
}

function validateAppKeyBody (body) {
  if (!body.appKey) return { ok: false, status: 400, payload: errorPayload('appKey required') }
  if (!isValidHexKey(body.appKey, 64)) {
    return { ok: false, status: 400, payload: errorPayload('appKey must be 64 hex characters') }
  }
  return { ok: true }
}

export function resolveCatalogManagementRoute (method, path) {
  const route = CATALOG_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return {
    ...route,
    authMessage: `Unauthorized — API key required for ${path}`
  }
}

export function resolvePendingCatalogRoute (method, path) {
  const route = CATALOG_PENDING_ROUTES[`${method} ${path}`]
  if (!route) return null
  return {
    ...route,
    authMessage: `Unauthorized — API key required for ${path}`
  }
}

export function buildPendingCatalogRoutePayload ({
  route,
  pendingRequests,
  resolveAcceptMode = null
} = {}) {
  if (!route || route.kind !== 'pending-catalog') {
    return {
      payload: { error: 'unknown pending catalog route' },
      status: 404
    }
  }

  return {
    payload: buildPendingCatalogPayload({ pendingRequests, resolveAcceptMode }),
    status: 200
  }
}

function safeString (value) {
  if (typeof value !== 'string') return null
  return value
}

function safeNumber (value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function safeBoolean (value) {
  return typeof value === 'boolean' ? value : null
}

function safeHexBuffer (value, bytes) {
  if (!value || typeof value.byteLength !== 'number') return null
  const buf = Buffer.from(value)
  if (typeof bytes === 'number' && buf.byteLength !== bytes) return null
  return buf.toString('hex')
}

function copyStringField (payload, entry, field) {
  const value = safeString(entry[field])
  if (value !== null) payload[field] = value
}

function copyNumberField (payload, entry, field) {
  const value = safeNumber(entry[field])
  if (value !== null) payload[field] = value
}

function copyBooleanField (payload, entry, field) {
  const value = safeBoolean(entry[field])
  if (value !== null) payload[field] = value
}

function copyStringArrayField (payload, entry, field) {
  if (!Array.isArray(entry[field])) return
  payload[field] = entry[field].filter(value => typeof value === 'string')
}

function pendingEntryObject (entry) {
  return entry && typeof entry === 'object' ? entry : {}
}

function pendingAppKey (appKey) {
  return typeof appKey === 'string' ? appKey : String(appKey)
}

function buildPendingCatalogRequest (appKey, rawEntry) {
  const entry = pendingEntryObject(rawEntry)
  const payload = { appKey: pendingAppKey(appKey) }

  const publisherPubkey = safeString(entry.publisherPubkey) || safeHexBuffer(entry.publisherPubkey, 32)
  if (publisherPubkey !== null) payload.publisherPubkey = publisherPubkey

  for (const field of [
    'source',
    'sourceRelay',
    'contentType',
    'type',
    'parentKey',
    'mountPath',
    'appId',
    'id',
    'version',
    'name',
    'author',
    'privacyTier',
    'storageClass',
    'availabilityClass',
    'mode'
  ]) {
    copyStringField(payload, entry, field)
  }

  for (const field of ['replicationFactor', 'currentRelays', 'discoveredAt']) {
    copyNumberField(payload, entry, field)
  }

  copyBooleanField(payload, entry, 'blind')
  copyStringArrayField(payload, entry, 'categories')

  return payload
}

export function buildPendingCatalogPayload ({
  pendingRequests,
  resolveAcceptMode = null
} = {}) {
  const requests = []
  if (pendingRequests && typeof pendingRequests[Symbol.iterator] === 'function') {
    for (const [appKey, entry] of pendingRequests) {
      requests.push(buildPendingCatalogRequest(appKey, entry))
    }
  }

  return {
    count: requests.length,
    mode: typeof resolveAcceptMode === 'function' ? resolveAcceptMode() : null,
    requests
  }
}

async function persistCatalogConfig ({ persistConfig, rollback }) {
  try {
    await persistConfig()
    return { ok: true }
  } catch (err) {
    rollback()
    return { ok: false, kind: 'config-persist', error: err }
  }
}

export async function runLegacyAutoAcceptAction ({
  body = {},
  config,
  persistConfig = async () => {},
  emit = null
}) {
  body = body || {}
  if (!config || typeof config !== 'object') {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Config not available') }
  }
  if (body.enabled !== undefined) {
    const result = validateBooleanField(body.enabled, 'enabled')
    if (!result.ok) return { ok: false, kind: 'bad-request', status: 400, payload: result.payload }
  }

  const snapshot = snapshotAcceptModeConfig(config)
  config.registryAutoAccept = body.enabled !== false
  delete config.acceptMode

  const persisted = await persistCatalogConfig({
    persistConfig,
    rollback: () => restoreAcceptModeConfig(config, snapshot, emit)
  })
  if (!persisted.ok) return persisted

  return {
    ok: true,
    payload: { ok: true, autoAccept: config.registryAutoAccept }
  }
}

export async function runCatalogModeAction ({
  body = {},
  config,
  persistConfig = async () => {},
  emit = null
}) {
  body = body || {}
  const mode = body.mode
  if (!CATALOG_ACCEPT_MODES.includes(mode)) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: errorPayload('mode must be one of: open, review, allowlist, closed')
    }
  }
  if (!config || typeof config !== 'object') {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Config not available') }
  }

  const snapshot = snapshotAcceptModeConfig(config)
  config.acceptMode = mode
  delete config.registryAutoAccept // disambiguate

  const persisted = await persistCatalogConfig({
    persistConfig,
    rollback: () => restoreAcceptModeConfig(config, snapshot, emit)
  })
  if (!persisted.ok) return persisted

  return {
    ok: true,
    payload: { ok: true, mode }
  }
}

export async function runCatalogAllowlistAction ({
  body = {},
  config,
  persistConfig = async () => {},
  emit = null
}) {
  body = body || {}
  if (!Array.isArray(body.allowlist)) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: errorPayload('allowlist must be an array of publisher pubkeys (hex)')
    }
  }

  for (const k of body.allowlist) {
    if (typeof k !== 'string' || !isValidHexKey(k, 64)) {
      return {
        ok: false,
        kind: 'bad-request',
        status: 400,
        payload: errorPayload('allowlist entries must be 64-char hex pubkeys')
      }
    }
  }

  if (!config || typeof config !== 'object') {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Config not available') }
  }

  const snapshot = snapshotAllowlistConfig(config)
  config.acceptAllowlist = body.allowlist
    .map(k => k.toLowerCase())
    .filter((key, index, list) => list.indexOf(key) === index)

  const persisted = await persistCatalogConfig({
    persistConfig,
    rollback: () => restoreAllowlistConfig(config, snapshot, emit)
  })
  if (!persisted.ok) return persisted

  return {
    ok: true,
    payload: { ok: true, allowlist: config.acceptAllowlist }
  }
}

export async function runCatalogAppAction ({
  action,
  body = {},
  node
}) {
  body = body || {}
  if (!['approve', 'reject', 'remove'].includes(action)) {
    return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload('Unknown catalog action') }
  }

  const valid = validateAppKeyBody(body)
  if (!valid.ok) return { ok: false, kind: 'bad-request', ...valid }

  if (!node) {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Relay node not available') }
  }

  if (action === 'approve') await node.approveRequest(body.appKey)
  else if (action === 'reject') await node.rejectRequest(body.appKey)
  else await node.unseedApp(body.appKey)

  return { ok: true, payload: { ok: true } }
}

export async function runRegistryCancelAction ({
  body = {},
  node
}) {
  body = body || {}
  if (!node || !node.seedingRegistry) {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Registry not running') }
  }

  const valid = validateAppKeyBody(body)
  if (!valid.ok) return { ok: false, kind: 'bad-request', ...valid }

  const pubkey = node.swarm ? Buffer.from(node.swarm.keyPair.publicKey).toString('hex') : null
  await node.seedingRegistry.cancelRequest(body.appKey, pubkey)
  return { ok: true, payload: { ok: true } }
}

export async function runCatalogManagementRouteAction ({
  route,
  body = {},
  config,
  node,
  persistConfig = async () => {},
  emit = null
} = {}) {
  if (!route) {
    return { ok: false, kind: 'not-found', status: 404, payload: errorPayload('unknown catalog management route') }
  }

  if (route.kind === 'legacy-auto-accept') {
    return runLegacyAutoAcceptAction({ body, config, persistConfig, emit })
  }

  if (route.kind === 'mode') {
    return runCatalogModeAction({ body, config, persistConfig, emit })
  }

  if (route.kind === 'allowlist') {
    return runCatalogAllowlistAction({ body, config, persistConfig, emit })
  }

  if (route.kind === 'app') {
    return runCatalogAppAction({ action: route.action, body, node })
  }

  if (route.kind === 'cancel') {
    return runRegistryCancelAction({ body, node })
  }

  return { ok: false, kind: 'not-found', status: 404, payload: errorPayload('unknown catalog management route') }
}
