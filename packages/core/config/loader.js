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

const PACKAGED_SERVICE_ENV = Object.freeze({
  HIVERELAY_VRF: 'vrf',
  HIVERELAY_NOTIFY: 'notify',
  HIVERELAY_OUTBOXLOG: 'outboxlog',
  HIVERELAY_STORAGE_PROOF: 'storage-proof',
  HIVERELAY_WITNESSLOG: 'witnesslog',
  HIVERELAY_REPAIRTICKET: 'repairticket',
  HIVERELAY_SHARD_STORE: 'shard-store'
})

/**
 * Translate the declarative environment shipped by Docker, systemd and
 * appliance packages into Node-runtime config defaults.
 *
 * Precedence is deliberately conservative: explicit CLI values and matching
 * config.json fields win. The storage-local services.json remains the final
 * services authority because RelayNode loads it immediately before plugins.
 * This makes package env useful on first boot without trapping an operator in
 * a permanent environment override.
 */
export function applyRuntimeEnvDefaults (
  cliOverrides = {},
  env = process.env,
  persistedConfig = readPersistedConfig(),
  { readTextFile = (path) => readFileSync(path, 'utf8') } = {}
) {
  const persisted = isPlainObject(persistedConfig) ? persistedConfig : {}

  const globalServices = parseOptionalBoolean(env.HIVERELAY_ENABLE_SERVICES, 'HIVERELAY_ENABLE_SERVICES')
  const persistedPlugins = hasOwn(persisted, 'plugins')
  const cliPlugins = hasOwn(cliOverrides, 'plugins')
  const selectedPlugins = []
  for (const [name, plugin] of Object.entries(PACKAGED_SERVICE_ENV)) {
    if (parseOptionalBoolean(env[name], name) === true) selectedPlugins.push(plugin)
  }
  if (!persistedPlugins && !cliPlugins && selectedPlugins.length > 0) {
    cliOverrides.plugins = selectedPlugins
  }
  if (!hasOwn(persisted, 'enableServices') && !hasOwn(cliOverrides, 'enableServices')) {
    if (globalServices !== undefined) cliOverrides.enableServices = globalServices
    else if (selectedPlugins.length > 0) cliOverrides.enableServices = true
  }

  const torEnabled = parseOptionalBoolean(env.HIVERELAY_TOR, 'HIVERELAY_TOR')
  if (torEnabled !== undefined &&
      !hasNestedOwn(persisted, 'transports', 'tor') &&
      !hasNestedOwn(cliOverrides, 'transports', 'tor')) {
    nestedObject(cliOverrides, 'transports').tor = torEnabled
  }
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_SOCKS_HOST', 'tor', 'socksHost')
  applyPortEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_SOCKS_PORT', 'tor', 'socksPort')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_CONTROL_HOST', 'tor', 'controlHost')
  applyPortEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_CONTROL_PORT', 'tor', 'controlPort')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_COOKIE_AUTH_FILE', 'tor', 'cookieAuthFile')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_KEY_FILE', 'tor', 'keyFile')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_MIN_DAEMON_VERSION', 'tor', 'minDaemonVersion')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_TOR_ROSTER_FILE', 'tor', 'rosterFile')

  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_OUTBOXLOG_JOURNAL', 'outboxlog', 'journal')
  applyStringEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_OUTBOXLOG_JOURNAL_PATH', 'outboxlog', 'journalPath')
  applyBooleanEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_OUTBOXLOG_LEGACY_WRITES', 'outboxlog', 'legacyWrites')
  applyBytesEnvDefault(cliOverrides, persisted, env, 'HIVERELAY_OUTBOXLOG_MAX_JOURNAL_STORAGE', 'outboxlog', 'maxJournalStorageBytes')

  const notifyPushPath = stringEnv(env.HIVERELAY_NOTIFY_PUSH_CONFIG)
  if (notifyPushPath &&
      !hasNestedOwn(persisted, 'notify', 'push') &&
      !hasNestedOwn(cliOverrides, 'notify', 'push')) {
    let descriptor
    try {
      descriptor = JSON.parse(readTextFile(notifyPushPath))
    } catch (err) {
      throw new Error(`Invalid HIVERELAY_NOTIFY_PUSH_CONFIG: ${err && err.message ? err.message : 'unreadable JSON'}`)
    }
    if (!isPlainObject(descriptor)) {
      throw new Error('Invalid HIVERELAY_NOTIFY_PUSH_CONFIG: expected a JSON object')
    }
    nestedObject(cliOverrides, 'notify').push = descriptor
  }

  return cliOverrides
}

function readPersistedConfig () {
  if (!existsSync(CONFIG_PATH)) return {}
  try {
    const parsed = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
    return isPlainObject(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

function parseOptionalBoolean (value, name) {
  if (value === undefined || value === null || value === '') return undefined
  const normalized = String(value).trim().toLowerCase()
  if (normalized === '1' || normalized === 'true') return true
  if (normalized === '0' || normalized === 'false') return false
  throw new Error(`Invalid ${name}: expected 1, 0, true, or false`)
}

function parsePositiveBytes (value, name) {
  const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 }
  const match = String(value || '').trim().match(/^(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB|B)?$/i)
  const bytes = match ? Math.floor(Number(match[1]) * units[(match[2] || 'B').toUpperCase()]) : NaN
  if (!Number.isSafeInteger(bytes) || bytes <= 0) {
    throw new Error(`Invalid ${name}: expected a positive size such as 512MB or 1GB`)
  }
  return bytes
}

function isPlainObject (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function hasOwn (value, key) {
  return isPlainObject(value) && Object.prototype.hasOwnProperty.call(value, key)
}

function hasNestedOwn (value, parent, key) {
  return hasOwn(value, parent) && hasOwn(value[parent], key)
}

function nestedObject (value, key) {
  if (!isPlainObject(value[key])) value[key] = {}
  return value[key]
}

function stringEnv (value) {
  if (value === undefined || value === null) return null
  const normalized = String(value).trim()
  return normalized || null
}

function applyStringEnvDefault (cli, persisted, env, envName, parent, key) {
  const value = stringEnv(env[envName])
  if (!value || hasNestedOwn(persisted, parent, key) || hasNestedOwn(cli, parent, key)) return
  nestedObject(cli, parent)[key] = value
}

function applyPortEnvDefault (cli, persisted, env, envName, parent, key) {
  const value = stringEnv(env[envName])
  if (!value || hasNestedOwn(persisted, parent, key) || hasNestedOwn(cli, parent, key)) return
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid ${envName}: expected an integer from 1 to 65535`)
  }
  nestedObject(cli, parent)[key] = port
}

function applyBooleanEnvDefault (cli, persisted, env, envName, parent, key) {
  const value = parseOptionalBoolean(env[envName], envName)
  if (value === undefined || hasNestedOwn(persisted, parent, key) || hasNestedOwn(cli, parent, key)) return
  nestedObject(cli, parent)[key] = value
}

function applyBytesEnvDefault (cli, persisted, env, envName, parent, key) {
  const value = stringEnv(env[envName])
  if (!value || hasNestedOwn(persisted, parent, key) || hasNestedOwn(cli, parent, key)) return
  nestedObject(cli, parent)[key] = parsePositiveBytes(value, envName)
}

/**
 * Load config: defaults < config.json < CLI overrides
 */
export function loadConfig (cliOverrides = {}) {
  const fileConfig = readPersistedConfig()

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
