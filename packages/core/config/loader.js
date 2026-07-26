/**
 * Configuration Loader
 *
 * Priority (highest first):
 *   1. CLI flags (passed as overrides)
 *   2. ~/.hiverelay/config.json (user config file)
 *   3. config/default.js (built-in defaults)
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'
import { createHmac } from 'crypto'
import defaults from './default.js'
import {
  getStorageCapProvenance,
  markStorageCapDefault,
  markStorageCapExplicit
} from './storage-cap.js'

const HIVERELAY_DIR = join(homedir(), '.hiverelay')
const CONFIG_PATH = join(HIVERELAY_DIR, 'config.json')
const STORAGE_DIR = join(HIVERELAY_DIR, 'storage')

export { HIVERELAY_DIR, CONFIG_PATH, STORAGE_DIR }
export {
  copyStorageCapProvenance,
  getStorageCapProvenance,
  markStorageCapDefault,
  markStorageCapExplicit,
  resolveStorageCap
} from './storage-cap.js'

/**
 * Derive a stable management token from a host-provided seed (e.g. the
 * `$APP_SEED` env var that self-hosting platforms like Umbrel inject —
 * deterministic per app-id, so it survives reinstalls). Domain-separated
 * from the wizard's identity/encryption key (`hiverelay/wizard/v1`) so the
 * two derivations can never collide. Returns a 64-char hex string, or null
 * if the seed is missing/too short to be useful.
 */
export function deriveTokenFromSeed (seed) {
  if (!seed || typeof seed !== 'string' || seed.length < 32) return null
  return createHmac('sha256', 'hiverelay/ui-token/v1')
    .update(Buffer.from(seed, 'utf8'))
    .digest('hex')
}

/**
 * Apply the HIVERELAY_OUTBOXLOG_NAMESPACE env var to CLI overrides.
 *
 * The app-neutral outboxlog rejects records signed under an unregistered
 * namespace (`unknown namespace`, 400). An ENV-driven operator (fleet/bern box
 * with HIVERELAY_OUTBOXLOG=1) needs a way to register the namespace their app
 * signs under (e.g. Peerit signs 'peerit'); this maps the env value to
 * config.outboxlog.namespace, which OutboxLogApp.start() feeds to the engine's
 * namespace registry.
 *
 * Precedence — env is a DEFAULT, not a permanent override, mirroring
 * HIVERELAY_ACCEPT_MODE / HIVERELAY_MAX_STORAGE. Because loadConfig()'s deep
 * merge is `defaults < config.json < cliOverrides`, applying the env
 * unconditionally would clobber a persisted config.json outboxlog.namespace.
 * So the env is only applied when the operator has NOT persisted an explicit
 * outboxlog.namespace (hasPersistedNamespace === false) and has not already set
 * one on cliOverrides. Mutates and returns cliOverrides.
 *
 * @param {object} cliOverrides - the mutable CLI-override object
 * @param {string|undefined} rawEnvValue - process.env.HIVERELAY_OUTBOXLOG_NAMESPACE
 * @param {boolean} hasPersistedNamespace - true if config.json already has outboxlog.namespace
 */
export function applyOutboxlogNamespaceEnv (cliOverrides = {}, rawEnvValue, hasPersistedNamespace = false) {
  if (!rawEnvValue || hasPersistedNamespace) return cliOverrides
  const namespace = String(rawEnvValue).trim()
  if (!namespace) return cliOverrides
  if (!cliOverrides.outboxlog || typeof cliOverrides.outboxlog !== 'object') {
    cliOverrides.outboxlog = {}
  }
  if (typeof cliOverrides.outboxlog.namespace !== 'string') {
    cliOverrides.outboxlog.namespace = namespace
  }
  return cliOverrides
}

/**
 * Load config: defaults < config.json < CLI overrides
 */
export function loadConfig (cliOverrides = {}) {
  let fileConfig = {}

  if (existsSync(CONFIG_PATH)) {
    try {
      fileConfig = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
    } catch {
      // Ignore malformed config file
    }
  }

  // Deep merge: defaults < file < CLI (preserves nested object keys)
  const config = deepMerge(deepMerge(defaults, fileConfig), cliOverrides)

  // Presence, not numeric equality, is provenance. In particular, an
  // explicitly configured 50 GiB cap must not be mistaken for the built-in
  // 50 GiB default and rewritten by disk-relative resolution.
  if (Object.prototype.hasOwnProperty.call(cliOverrides, 'maxStorageBytes')) {
    const overrideProvenance = getStorageCapProvenance(cliOverrides)
    markStorageCapExplicit(config, overrideProvenance?.source || 'cli')
  } else if (Object.prototype.hasOwnProperty.call(fileConfig, 'maxStorageBytes')) {
    markStorageCapExplicit(config, 'persisted')
  } else {
    markStorageCapDefault(config)
  }

  // Always resolve storage to absolute path
  if (config.storage === defaults.storage && fileConfig.storage == null && cliOverrides.storage == null) {
    config.storage = STORAGE_DIR
  }

  return config
}

/**
 * Write config to ~/.hiverelay/config.json
 */
export function saveConfig (config) {
  mkdirSync(HIVERELAY_DIR, { recursive: true })
  mkdirSync(STORAGE_DIR, { recursive: true })

  // Only persist non-default values
  const toSave = {}
  const storageCapProvenance = getStorageCapProvenance(config)
  for (const [key, val] of Object.entries(config)) {
    if (key === 'maxStorageBytes') {
      // A resolved default may be below 50 GiB. Persisting that derived value
      // would turn it into an operator designation on restart and ratchet the
      // cap down again. Explicit values, including exactly 50 GiB, must always
      // be written.
      const explicit = storageCapProvenance
        ? storageCapProvenance.explicit === true
        : Object.prototype.hasOwnProperty.call(config, 'maxStorageBytes')
      if (explicit) toSave[key] = val
      continue
    }
    if (JSON.stringify(val) !== JSON.stringify(defaults[key])) {
      toSave[key] = val
    }
  }

  writeFileSync(CONFIG_PATH, JSON.stringify(toSave, null, 2) + '\n')
  return CONFIG_PATH
}

/**
 * Ensure ~/.hiverelay directory structure exists
 */
export function ensureDirs () {
  mkdirSync(HIVERELAY_DIR, { recursive: true })
  mkdirSync(STORAGE_DIR, { recursive: true })
}

/**
 * Recursively merge source into target, preserving sibling keys in nested objects.
 */
function deepMerge (target, source) {
  const result = cloneConfigValue(target)
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue
    if (
      source[key] && typeof source[key] === 'object' && !Array.isArray(source[key]) &&
      result[key] && typeof result[key] === 'object' && !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(result[key], source[key])
    } else {
      result[key] = cloneConfigValue(source[key])
    }
  }
  return result
}

function cloneConfigValue (value) {
  if (Array.isArray(value)) return value.map(cloneConfigValue)
  if (!value || typeof value !== 'object') return value

  const out = {}
  for (const key of Object.keys(value)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue
    out[key] = cloneConfigValue(value[key])
  }
  return out
}
