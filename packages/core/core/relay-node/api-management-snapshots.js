import { AVAILABLE_MODES } from './api-mode-transport.js'
import { sanitizeDeviceList } from './api-device-pairing.js'
import { buildSafeConfigPayload } from './api-safe-config.js'
import { serviceConfigPayload } from './api-service-config.js'
import { runManageAIModelsListAction } from './api-ai-models.js'

export const MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES = 128
export const MAX_MANAGEMENT_SERVICE_METHODS = 64
export const MAX_MANAGEMENT_SERVICE_LABEL_BYTES = 128
export const MAX_MANAGEMENT_SERVICE_ERROR_BYTES = 512
export const MAX_MANAGEMENT_SERVICE_STATS_DEPTH = 3
export const MAX_MANAGEMENT_SERVICE_STATS_KEYS = 32
export const MAX_MANAGEMENT_SERVICE_STATS_ARRAY = 32
export const MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES = 256
export const MAX_MANAGEMENT_SERVICE_STATS_NODES = 256

const SENSITIVE_STATS_KEY = /(?:secret|token|password|credential|authorization|bearer|private|app[_-]?seed|api[_-]?key|connection[_-]?key|public[_-]?key)/i
const MANAGEMENT_SNAPSHOT_ROUTES = Object.freeze({
  'GET /api/manage/config': Object.freeze({ kind: 'config' }),
  'GET /api/manage/ai/models': Object.freeze({ kind: 'ai-models' }),
  'GET /api/manage/services/available': Object.freeze({ kind: 'service-config' }),
  'GET /api/manage/services': Object.freeze({ kind: 'services' }),
  'GET /api/manage/transports': Object.freeze({ kind: 'transports' }),
  'GET /api/manage/devices': Object.freeze({ kind: 'devices' }),
  'GET /api/manage/pairing': Object.freeze({ kind: 'pairing' }),
  'GET /api/manage/modes': Object.freeze({ kind: 'modes' })
})

const MODE_DETAILS = Object.freeze({
  'relay-core': Object.freeze({
    name: 'Relay Core',
    description: 'Default focused kernel — availability, registry, gateway, custody, no service plugins'
  }),
  relaykernel: Object.freeze({
    name: 'RelayKernel Profile',
    description: 'Narrow seed/proof/circuit/meta/accounting profile — custody, services, federation, and global directory surfaces off'
  }),
  'custody-relay': Object.freeze({
    name: 'Custody Relay',
    description: 'Blind atomic custody profile — encrypted temporary handoff and expiry proofs'
  }),
  public: Object.freeze({
    name: 'Public',
    description: 'Public relay defaults with open access'
  }),
  standard: Object.freeze({
    name: 'Standard Relay',
    description: 'Legacy alias for Relay Core defaults'
  }),
  private: Object.freeze({
    name: 'Private',
    description: 'LAN-friendly closed mode with allowlist and pairing'
  }),
  hybrid: Object.freeze({
    name: 'Hybrid',
    description: 'Public discovery with private admission control'
  }),
  homehive: Object.freeze({
    name: 'HomeHive',
    description: 'Home/personal relay — LAN priority, low resources, family-friendly'
  }),
  'seed-only': Object.freeze({
    name: 'Seed Only',
    description: 'App seeding only — no circuit relay'
  }),
  'relay-only': Object.freeze({
    name: 'Relay Only',
    description: 'Circuit relay only — no app seeding'
  }),
  stealth: Object.freeze({
    name: 'Stealth',
    description: 'Tor-only, minimal footprint, no HTTP API on clearnet'
  }),
  gateway: Object.freeze({
    name: 'Gateway',
    description: 'HTTP gateway focus — serve Hyperdrive content over HTTPS'
  }),
  'service-operator': Object.freeze({
    name: 'Service Operator',
    description: 'Opt-in service plugin host on top of the relay core'
  }),
  'experimental-lab': Object.freeze({
    name: 'Experimental Lab',
    description: 'AI/ZK/SLA/arbitration plugin playground, not a default production profile'
  })
})

export function resolveManagementSnapshotRoute (method, path) {
  const route = MANAGEMENT_SNAPSHOT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildServiceRegistrySnapshot (registry) {
  if (!registry || !registry.services || typeof registry.services[Symbol.iterator] !== 'function') {
    return { services: [], count: 0 }
  }

  const services = []
  for (const [name, entry] of registry.services) {
    if (services.length >= MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES) break
    services.push(buildServiceEntrySnapshot(name, entry))
  }
  return {
    services,
    count: services.length,
    total: registry.services.size || services.length,
    truncated: (registry.services.size || services.length) > services.length
  }
}

export function buildManagementConfigPayload (node) {
  return {
    config: buildSafeConfigPayload(node),
    mode: node && node._operatingMode ? node._operatingMode : 'standard'
  }
}

export function buildManagementServicesPayload (registry) {
  const snapshot = buildServiceRegistrySnapshot(registry)
  return {
    enabled: !!registry,
    ...snapshot,
    statsVerified: false,
    services: snapshot.services.map(service => ({
      ...service,
      capabilities: Array.isArray(service.methods) ? service.methods : []
    }))
  }
}

export async function buildManagementSnapshotRoutePayload ({
  route,
  node,
  aiModelProvider = null,
  emit = null
} = {}) {
  const kind = route && route.kind
  if (kind === 'config') return { ok: true, payload: buildManagementConfigPayload(node) }
  if (kind === 'ai-models') {
    if (!aiModelProvider || !aiModelProvider.ok) {
      return {
        ok: false,
        status: aiModelProvider && aiModelProvider.status ? aiModelProvider.status : 503,
        payload: { error: aiModelProvider && aiModelProvider.error ? aiModelProvider.error : 'AI service is not registered on this relay' }
      }
    }
    return runManageAIModelsListAction({
      provider: aiModelProvider.provider,
      emit
    })
  }
  if (kind === 'service-config') {
    return { ok: true, payload: serviceConfigPayload(node && node.config, node && node.serviceRegistry) }
  }
  if (kind === 'services') return { ok: true, payload: buildManagementServicesPayload(node && node.serviceRegistry) }
  if (kind === 'transports') return { ok: true, payload: buildTransportStatusPayload(node) }
  if (kind === 'devices') return { ok: true, payload: buildDeviceStatusPayload(node) }
  if (kind === 'pairing') return { ok: true, payload: buildPairingStatusPayload(node) }
  if (kind === 'modes') return { ok: true, payload: buildModeCatalogPayload(node && node._operatingMode ? node._operatingMode : 'relay-core') }
  return {
    ok: false,
    status: 404,
    payload: { error: 'unknown management snapshot route' }
  }
}

export function buildServiceEntrySnapshot (name, entry = {}) {
  const provider = entry.provider || entry
  const rawMethods = Array.isArray(entry.capabilities) && entry.capabilities.length > 0
    ? entry.capabilities
    : (provider && provider.methods ? Object.keys(provider.methods) : [])
  let providerStats = null
  if (provider && typeof provider.stats === 'function') {
    try { providerStats = provider.stats() } catch (_) {}
  }

  return {
    name: safeSnapshotString(name, MAX_MANAGEMENT_SERVICE_LABEL_BYTES) || 'unknown',
    version: safeSnapshotString(entry.version, MAX_MANAGEMENT_SERVICE_LABEL_BYTES) || null,
    description: safeSnapshotString(entry.description, MAX_MANAGEMENT_SERVICE_LABEL_BYTES, {
      allowEmpty: true,
      trim: false
    }) || '',
    status: safeSnapshotString(entry.status, MAX_MANAGEMENT_SERVICE_LABEL_BYTES) || (entry.running ? 'running' : 'unknown'),
    running: entry.status === 'running' || entry.running === true,
    methods: sanitizeMethods(rawMethods),
    stats: sanitizeStats(entry.stats || providerStats),
    restartCount: safeCount(entry.restartCount),
    lastStartedAt: safeSnapshotString(entry.lastStartedAt, MAX_MANAGEMENT_SERVICE_LABEL_BYTES) || null,
    lastStoppedAt: safeSnapshotString(entry.lastStoppedAt, MAX_MANAGEMENT_SERVICE_LABEL_BYTES) || null,
    lastError: safeSnapshotString(errorMessage(entry.lastError), MAX_MANAGEMENT_SERVICE_ERROR_BYTES, {
      allowEmpty: false,
      trim: false
    }) || null
  }
}

function sanitizeMethods (methods) {
  const list = Array.isArray(methods) ? methods : []
  const out = []
  const seen = new Set()
  for (const method of list) {
    if (out.length >= MAX_MANAGEMENT_SERVICE_METHODS) break
    const value = safeSnapshotString(method, MAX_MANAGEMENT_SERVICE_LABEL_BYTES)
    if (!value || seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function sanitizeStats (value) {
  const state = { nodes: 0 }
  const clean = sanitizeStatsValue(value, 0, state)
  return clean === undefined ? null : clean
}

function sanitizeStatsValue (value, depth, state) {
  if (state.nodes++ >= MAX_MANAGEMENT_SERVICE_STATS_NODES) return undefined
  if (value === null) return null
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined
  if (typeof value === 'string') {
    return safeSnapshotString(value, MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES, {
      trim: false
    }) || undefined
  }
  if (typeof value !== 'object') return undefined
  if (depth >= MAX_MANAGEMENT_SERVICE_STATS_DEPTH) return undefined

  if (Array.isArray(value)) {
    const out = []
    for (const item of value) {
      if (out.length >= MAX_MANAGEMENT_SERVICE_STATS_ARRAY) break
      const clean = sanitizeStatsValue(item, depth + 1, state)
      if (clean !== undefined) out.push(clean)
    }
    return out
  }

  const out = {}
  for (const [rawKey, child] of Object.entries(value)) {
    if (Object.keys(out).length >= MAX_MANAGEMENT_SERVICE_STATS_KEYS) break
    const key = safeStatsKey(rawKey)
    if (!key) continue
    const clean = sanitizeStatsValue(child, depth + 1, state)
    if (clean !== undefined) out[key] = clean
  }
  return out
}

function safeStatsKey (value) {
  const key = safeSnapshotString(value, MAX_MANAGEMENT_SERVICE_LABEL_BYTES)
  if (!key || SENSITIVE_STATS_KEY.test(key)) return null
  return key
}

function safeCount (value) {
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

function errorMessage (value) {
  if (value == null) return null
  if (value instanceof Error) return value.message
  return value
}

function safeSnapshotString (value, maxBytes, opts = {}) {
  if (typeof value !== 'string') return null
  const text = opts.trim === false ? value : value.trim()
  if (!text && opts.allowEmpty !== true) return null
  if (hasControlChar(text)) return null
  return truncateUtf8(text, maxBytes)
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function truncateUtf8 (value, maxBytes) {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = Buffer.byteLength(ch, 'utf8')
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

export function buildTransportStatusPayload (node) {
  const config = node && node.config ? node.config : {}
  return {
    udp: true,
    holesail: {
      enabled: !!(node && node.holesailTransport),
      connectionKey: node && node.holesailTransport
        ? node.holesailTransport.connectionKey
        : null,
      running: node && node.holesailTransport
        ? node.holesailTransport.running
        : false
    },
    tor: {
      enabled: !!(node && node.torTransport),
      onionAddress: node && node.torTransport
        ? node.torTransport.onionAddress
        : null,
      running: node && node.torTransport
        ? node.torTransport.running
        : false
    },
    websocket: {
      enabled: !!(config.transports && config.transports.websocket),
      port: config.wsPort || 8765
    }
  }
}

export function buildDeviceStatusPayload (node) {
  if (!node || !node.accessControl) {
    return {
      enabled: false,
      mode: node ? node.mode : undefined,
      devices: []
    }
  }

  const source = typeof node.listDevices === 'function' ? node.listDevices() : []
  const devices = sanitizeDeviceList(source)
  return {
    enabled: true,
    mode: node.mode,
    count: devices.length,
    total: Array.isArray(source) ? source.length : devices.length,
    truncated: Array.isArray(source) && source.length > devices.length,
    devices
  }
}

export function buildPairingStatusPayload (node) {
  if (!node || !node.accessControl) {
    return {
      enabled: false,
      mode: node ? node.mode : undefined,
      pairing: null
    }
  }

  const state = node.accessControl._pairingState
  return {
    enabled: true,
    mode: node.mode,
    pairing: state
      ? {
          active: !!node.accessControl.isPairing,
          expiresAt: state.expiresAt
        }
      : { active: false, expiresAt: null }
  }
}

export function buildModeCatalogPayload (current = 'relay-core') {
  return {
    current,
    available: AVAILABLE_MODES.map(id => ({
      id,
      name: MODE_DETAILS[id].name,
      description: MODE_DETAILS[id].description
    }))
  }
}
