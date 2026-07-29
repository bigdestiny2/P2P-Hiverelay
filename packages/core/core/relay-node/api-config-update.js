import { validatePositiveInt, validatePositiveNumber } from './api-validation.js'
import {
  copyStorageCapProvenance,
  markStorageCapExplicit,
  STORAGE_CAP_PROVENANCE
} from '../../config/storage-cap.js'

const INT_FIELDS = {
  maxStorageBytes: { min: 1048576, max: 10e12 },
  maxConnections: { min: 1, max: 100000 },
  maxCircuitsPerPeer: { min: 1, max: 1000 },
  maxCircuitDuration: { min: 1000, max: 86400000 },
  maxCircuitBytes: { min: 1024, max: 10e12 },
  announceInterval: { min: 1000, max: 3600000 },
  replicationCheckInterval: { min: 10000, max: 3600000 },
  targetReplicaFloor: { min: 1, max: 16 },
  catalogSignatureMaxAgeMs: { min: 1000, max: 86400000 },
  catalogMaxAppAgeMs: { min: 0, max: 31536000000 },
  shutdownTimeoutMs: { min: 1000, max: 300000 }
}

const BOOLEAN_FIELDS = [
  'registryAutoAccept',
  'replicationRepairEnabled',
  'gatewayPublicOnlyPrivacyTier',
  'strictSeedingPrivacy',
  'enableDistributedDriveBridge'
]

const OBJECT_MERGE_FIELDS = [
  'discovery',
  'access',
  'pairing'
]
const CONFIG_UPDATE_ROUTES = Object.freeze({
  'POST /api/manage/config': Object.freeze({ kind: 'config-update' })
})

function errorPayload (message) {
  return { error: message }
}

export function resolveConfigUpdateRoute (method, path) {
  const route = CONFIG_UPDATE_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function objectRecord (value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function validateRegions (regions) {
  if (!Array.isArray(regions)) return { ok: false, error: 'regions must be an array of strings' }
  if (regions.length > 64) return { ok: false, error: 'regions must contain at most 64 entries' }
  const out = []
  for (const region of regions) {
    if (typeof region !== 'string') return { ok: false, error: 'regions must be an array of strings' }
    const value = region.trim()
    if (!value) continue
    if (value.length > 64) return { ok: false, error: 'regions entries must be at most 64 characters' }
    out.push(value)
  }
  return { ok: true, regions: out }
}

function validateBooleanField (value, field) {
  if (typeof value !== 'boolean') return { ok: false, error: `${field} must be a boolean` }
  return { ok: true, value }
}

function rollbackApplied ({ applied, config, previousConfig }) {
  for (const field of applied) {
    if (Object.prototype.hasOwnProperty.call(previousConfig, field)) config[field] = previousConfig[field]
    else delete config[field]
  }
  if (previousConfig[STORAGE_CAP_PROVENANCE]) copyStorageCapProvenance(previousConfig, config)
  else delete config[STORAGE_CAP_PROVENANCE]
}

export async function runConfigUpdateAction ({
  body,
  config,
  persistConfig = async () => {},
  safeConfigPayload = () => config
}) {
  body = body || {}

  const applied = []
  const previousConfig = { ...config }
  const rollback = () => rollbackApplied({ applied, config, previousConfig })

  for (const [field, bounds] of Object.entries(INT_FIELDS)) {
    if (body[field] !== undefined) {
      const result = validatePositiveInt(body[field], bounds.min, bounds.max, field)
      if (!result.ok) {
        rollback()
        return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
      }
      config[field] = result.value
      if (field === 'maxStorageBytes') markStorageCapExplicit(config, 'management-api')
      applied.push(field)
    }
  }

  if (body.maxRelayBandwidthMbps !== undefined) {
    const result = validatePositiveNumber(body.maxRelayBandwidthMbps, 0.1, 100000, 'maxRelayBandwidthMbps')
    if (!result.ok) {
      rollback()
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
    }
    config.maxRelayBandwidthMbps = result.value
    applied.push('maxRelayBandwidthMbps')
  }

  for (const field of BOOLEAN_FIELDS) {
    if (body[field] !== undefined) {
      const result = validateBooleanField(body[field], field)
      if (!result.ok) {
        rollback()
        return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
      }
      config[field] = result.value
      applied.push(field)
    }
  }

  if (body.requireSignedCatalog !== undefined) {
    const result = validateBooleanField(body.requireSignedCatalog, 'requireSignedCatalog')
    if (!result.ok) {
      rollback()
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
    }
    config.requireSignedCatalog = result.value
    applied.push('requireSignedCatalog')
  }

  if (body.regions !== undefined) {
    const result = validateRegions(body.regions)
    if (!result.ok) {
      rollback()
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(result.error) }
    }
    config.regions = result.regions
    applied.push('regions')
  }

  for (const field of OBJECT_MERGE_FIELDS) {
    if (body[field] !== undefined) {
      if (!objectRecord(body[field])) {
        rollback()
        return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(`${field} must be an object`) }
      }
      config[field] = {
        ...(objectRecord(config[field]) ? config[field] : {}),
        ...body[field]
      }
      applied.push(field)
    }
  }

  try {
    await persistConfig()
  } catch (err) {
    rollback()
    return { ok: false, kind: 'config-persist', error: err }
  }

  return {
    ok: true,
    payload: {
      ok: true,
      applied,
      config: safeConfigPayload()
    }
  }
}
