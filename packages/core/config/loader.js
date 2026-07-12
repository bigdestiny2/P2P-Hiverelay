/**
 * Configuration Loader
 *
 * Priority (highest first):
 *   1. CLI flags (passed as overrides)
 *   2. ~/.hiverelay/config.json (user config file)
 *   3. config/default.js (built-in defaults)
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, statfsSync } from 'fs'
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

// Storage-cap safety fractions of the volume. The built-in default
// (config/default.js maxStorageBytes = 50 GB) is a FIXED value that does not
// scale to the disk — on a small box it is too big: a 58 GB box with a 50 GB
// seeded cap fills the disk to 100% (seeded bytes + gateway store + OS + Hypercore
// overhead) BEFORE the 50 GB cap binds, wedging the node (writes fail → /health
// hangs → public 502). See the 2026-07 relay-us disk-full incident. So we make an
// UNSET cap scale to the actual disk, and clamp any explicit cap that would risk
// filling the volume.
const DEFAULT_STORAGE_DISK_FRACTION = 0.75 // unset cap → 75% of the volume
const MAX_STORAGE_DISK_FRACTION = 0.90 // hard ceiling any explicit cap is clamped to

function existingAncestor (p) {
  let cur = p
  for (let i = 0; i < 64 && cur; i++) {
    if (existsSync(cur)) return cur
    const parent = join(cur, '..')
    if (parent === cur) break
    cur = parent
  }
  return cur
}

/**
 * Resolve a disk-relative storage cap so an unset maxStorageBytes scales to the
 * actual volume instead of the fixed 50 GB default. Rules:
 *   - unset (equals the built-in default): cap = 75% of total disk.
 *   - explicit but > 90% of disk: clamped to 90% (config._maxStorageBytesClampedFrom
 *     records the original so the CLI can warn).
 *   - disk unmeasurable / non-positive: config is left unchanged (safe fallback to
 *     the merged value — never make the cap worse than it already was).
 *
 * Pure and testable: pass `opts.statfs` (a statfsSync-shaped fn returning
 * { blocks, bsize }) to simulate a volume; defaults to fs.statfsSync of the
 * storage path's nearest existing ancestor. Mutates and returns `config`.
 */
export function resolveStorageCap (config, opts = {}) {
  const statfs = opts.statfs || statfsSync
  const target = opts.storagePath || (config && config.storage) || STORAGE_DIR
  let totalBytes = 0
  try {
    const s = statfs(existingAncestor(target))
    totalBytes = Number(s.blocks) * Number(s.bsize)
  } catch {
    totalBytes = 0
  }
  if (!Number.isFinite(totalBytes) || totalBytes <= 0) return config

  const diskDefault = Math.floor(totalBytes * DEFAULT_STORAGE_DISK_FRACTION)
  const diskCeiling = Math.floor(totalBytes * MAX_STORAGE_DISK_FRACTION)
  const isDefault = config.maxStorageBytes === defaults.maxStorageBytes

  if (isDefault) {
    config.maxStorageBytes = diskDefault
  } else if (typeof config.maxStorageBytes === 'number' && config.maxStorageBytes > diskCeiling) {
    config._maxStorageBytesClampedFrom = config.maxStorageBytes
    config.maxStorageBytes = diskCeiling
  }
  return config
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
