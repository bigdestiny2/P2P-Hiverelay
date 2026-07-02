import { isValidHexKey } from '../constants.js'

export const SEED_CORE_AUTH_MESSAGE = 'Unauthorized — API key required for /seed-core'

export function normalizeSeedCoreKey (body = {}) {
  const raw = typeof body.coreKey === 'string'
    ? body.coreKey
    : (typeof body.appKey === 'string' ? body.appKey : null)
  if (raw === null) return null

  const coreKey = raw.trim().toLowerCase()
  return isValidHexKey(coreKey, 64) ? coreKey : null
}

export function resolveSeedCoreRoute (method, path) {
  if (method !== 'POST') return null
  if (path === '/seed-core') {
    return {
      kind: 'seed-core',
      authMessage: SEED_CORE_AUTH_MESSAGE
    }
  }
  return null
}

export async function runSeedCoreAction ({ node, body = {} } = {}) {
  if (!node || !node.seeder || typeof node.seeder.seedCore !== 'function') {
    return { ok: false, status: 503, payload: { error: 'seeder not available' } }
  }

  const coreKey = normalizeSeedCoreKey(body)
  if (!coreKey) {
    return { ok: false, status: 400, payload: { error: 'coreKey must be 64 hex characters' } }
  }

  try {
    const entry = await node.seeder.seedCore(coreKey)
    let catalogBee = false
    if (body.catalog === true && typeof node.setCatalogBeeKey === 'function') {
      await node.setCatalogBeeKey(coreKey)
      catalogBee = true
    }
    return {
      ok: true,
      status: 200,
      payload: {
        ok: true,
        coreKey,
        length: entry && entry.core ? entry.core.length : 0,
        catalogBee
      }
    }
  } catch (err) {
    return { ok: false, kind: 'seed-error', error: err }
  }
}
