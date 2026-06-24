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

const HIVERELAY_DIR = join(homedir(), '.hiverelay')
const CONFIG_PATH = join(HIVERELAY_DIR, 'config.json')
const STORAGE_DIR = join(HIVERELAY_DIR, 'storage')

export { HIVERELAY_DIR, CONFIG_PATH, STORAGE_DIR }

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
  for (const [key, val] of Object.entries(config)) {
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
