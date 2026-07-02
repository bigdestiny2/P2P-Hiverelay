/**
 * PluginLoader — Config-driven plugin architecture for services
 *
 * Loads service providers from config instead of hardcoding imports.
 * Builtin shortnames (e.g. 'ai', 'identity') resolve to classes exported by
 * the optional `p2p-hiveservices` package — Core itself ships no service
 * implementations. If `p2p-hiveservices` is not installed and an operator
 * lists a builtin shortname, the loader throws a clear error.
 *
 * Config examples:
 *   plugins: ['storage', 'identity', 'ai']              // builtin shortnames
 *   plugins: ['./my-plugin.js']                         // path to module
 *   plugins: [{ path: './my-plugin.js', options: {} }]  // with options
 */

import { join } from 'path'
import { pathToFileURL } from 'url'

// Builtin shortname -> { module subpath of p2p-hiveservices, exported className }
const BUILTIN_MAP = {
  storage: { module: 'p2p-hiveservices/builtin/storage-service.js', className: 'StorageService' },
  identity: { module: 'p2p-hiveservices/builtin/identity-service.js', className: 'IdentityService' },
  ai: { module: 'p2p-hiveservices/builtin/ai-service.js', className: 'AIService' },
  zk: { module: 'p2p-hiveservices/builtin/zk-service.js', className: 'ZKService' },
  sla: { module: 'p2p-hiveservices/builtin/sla-service.js', className: 'SLAService' },
  schema: { module: 'p2p-hiveservices/builtin/schema-service.js', className: 'SchemaService' },
  arbitration: { module: 'p2p-hiveservices/builtin/arbitration-service.js', className: 'ArbitrationService' },
  vrf: { module: 'p2p-hiveservices/builtin/vrf-service.js', className: 'VRFService' },
  // Card-blind poker substrate (SignedLog). Useful only with its crypto
  // support services — see SERVICE_BUNDLES below.
  poker: { module: 'p2p-hiveservices/builtin/poker/index.js', className: 'PokerApp' },
  // Single-writer app outbox availability bridge for Pear/PearBrowser apps.
  outboxlog: { module: 'p2p-hiveservices/builtin/outboxlog/index.js', className: 'OutboxLogApp' },
  // Encrypted wake-only notification bridge. Provider SDK adapters are
  // service-owned; Core only loads the optional provider.
  notify: { module: 'p2p-hiveservices/builtin/notify-service.js', className: 'NotifyService' },
  // Tier-2 trustless seed verification: signed challenge-response proof that
  // this relay holds a seeded block. Independent — NOT part of any bundle.
  'storage-proof': { module: 'p2p-hiveservices/builtin/storage-proof-service.js', className: 'StorageProofService' }
}

// Names operators can add as services (the Services tab's "available" list).
export const BUILTIN_SERVICE_NAMES = Object.keys(BUILTIN_MAP)

// One-click service bundles surfaced in the dashboard. Enabling a bundle key
// implies its support services are enabled too (a poker substrate is useless
// without verifiable randomness, dispute arbitration, and ZK proofs). Defined
// ONCE here so the UI ("Enable Poker services" button) and the backend
// (setServicesConfig auto-union) share a single source of truth — no drift.
export const SERVICE_BUNDLES = {
  poker: ['poker', 'vrf', 'arbitration', 'zk']
}

// Expand a plugins list so every bundle member pulls in its support services.
// Idempotent, deduped, builtins-only. An operator can't half-enable poker
// without the services it depends on.
export function expandServiceDeps (plugins) {
  const set = new Set((Array.isArray(plugins) ? plugins : []).map(String))
  for (const [key, members] of Object.entries(SERVICE_BUNDLES)) {
    if (set.has(key)) for (const m of members) set.add(m)
  }
  return [...set].filter((p) => BUILTIN_SERVICE_NAMES.includes(p))
}

export class PluginLoader {
  constructor (opts = {}) {
    this.plugins = []
    this._builtinDir = opts.builtinDir || null
  }

  /**
   * Load plugins from a config array.
   * Each entry can be:
   *   - A string name matching a builtin (e.g. 'ai', 'storage', 'identity')
   *   - A string path (relative or absolute) to a module with a default export
   *   - An object { path, options } for plugins needing config
   */
  async load (pluginConfigs, context = {}) {
    const providers = []

    for (const entry of expandPluginConfigs(pluginConfigs)) {
      let provider

      if (typeof entry === 'string') {
        if (entry === '__proto__' || entry === 'constructor' || entry === 'prototype') {
          throw new Error('PluginLoader: invalid plugin name')
        }
        if (BUILTIN_MAP[entry]) {
          provider = await this.loadBuiltin(entry, context)
        } else {
          provider = await this._loadFromPath(entry)
        }
      } else if (entry && typeof entry === 'object') {
        if (entry.path) {
          provider = await this._loadFromPath(entry.path, entry.options)
        } else {
          throw new Error('PluginLoader: object entry must have a "path" property')
        }
      } else {
        throw new Error('PluginLoader: invalid plugin config entry: ' + String(entry))
      }

      this.validate(provider)
      this.plugins.push(provider)
      providers.push(provider)
    }

    return providers
  }

  /**
   * Load a single builtin service by shortname. Resolves to a class exported by
   * the p2p-hiveservices package (which must be installed alongside Core).
   *
   * @param {string} name - One of: storage, identity, ai, zk, sla, schema, arbitration
   * @param {object} context - Optional context passed to constructors that need it
   * @returns {object} Instantiated service provider
   */
  async loadBuiltin (name, context = {}) {
    const info = BUILTIN_MAP[name]
    if (!info) {
      throw new Error('PluginLoader: unknown builtin "' + name + '"')
    }

    let mod
    try {
      mod = await import(info.module)
    } catch (err) {
      throw new Error(
        'PluginLoader: builtin "' + name + '" requires p2p-hiveservices to be installed. ' +
        'Install it with: npm install p2p-hiveservices. (' + err.message + ')'
      )
    }
    const Ctor = mod[info.className]

    if (!Ctor) {
      throw new Error('PluginLoader: builtin "' + name + '" missing export ' + info.className)
    }

    return new Ctor(context.constructorOpts || {})
  }

  /**
   * Load a plugin from a file path.
   * Expects the module to have a default export (class or factory).
   */
  async _loadFromPath (modulePath, options = {}) {
    if (typeof modulePath !== 'string') {
      throw new Error('PluginLoader: modulePath must be a string')
    }
    if (modulePath.includes('\0')) {
      throw new Error('PluginLoader: modulePath contains invalid characters')
    }
    if (modulePath === '__proto__' || modulePath === 'constructor' || modulePath === 'prototype') {
      throw new Error('PluginLoader: invalid modulePath')
    }
    if (modulePath.includes('..')) {
      throw new Error('PluginLoader: modulePath cannot contain ".."')
    }

    let resolved = modulePath
    if (!modulePath.startsWith('file://')) {
      if (modulePath.startsWith('/')) {
        const cwd = process.cwd()
        if (!modulePath.startsWith(cwd)) {
          throw new Error('PluginLoader: absolute paths outside of working directory are not allowed')
        }
        resolved = pathToFileURL(modulePath).href
      } else {
        resolved = pathToFileURL(join(process.cwd(), modulePath)).href
      }
    }

    const mod = await import(resolved)
    const Ctor = mod.default
    if (!Ctor) {
      throw new Error('PluginLoader: module at "' + modulePath + '" has no default export')
    }

    if (typeof Ctor === 'function') {
      return new Ctor(options)
    }

    // If it's already an instance, return as-is
    return Ctor
  }

  /**
   * Validate that a provider conforms to the ServiceProvider interface.
   * Must have manifest(), start(), stop() methods.
   * manifest() must return an object with name and version.
   */
  validate (provider) {
    if (typeof provider.manifest !== 'function') {
      throw new Error('PluginLoader: provider missing manifest() method')
    }
    if (typeof provider.start !== 'function') {
      throw new Error('PluginLoader: provider missing start() method')
    }
    if (typeof provider.stop !== 'function') {
      throw new Error('PluginLoader: provider missing stop() method')
    }

    const m = provider.manifest()
    if (!m || typeof m.name !== 'string' || !m.name) {
      throw new Error('PluginLoader: manifest() must return { name: string, version: string }')
    }
    if (typeof m.version !== 'string' || !m.version) {
      throw new Error('PluginLoader: manifest().version must be a non-empty string')
    }
  }

  /**
   * Stop all loaded plugins in reverse order.
   */
  async stopAll () {
    const reversed = this.plugins.slice().reverse()
    for (const provider of reversed) {
      await provider.stop()
    }
    this.plugins = []
  }
}

export function expandPluginConfigs (pluginConfigs) {
  const out = []
  const seenBuiltins = new Set()

  const pushBuiltin = (entry) => {
    if (seenBuiltins.has(entry)) return
    seenBuiltins.add(entry)
    out.push(entry)
  }

  const push = (entry) => {
    if (typeof entry === 'string') {
      const bundle = SERVICE_BUNDLES[entry]
      if (bundle) {
        for (const bundled of bundle) {
          if (bundled === entry && BUILTIN_MAP[bundled]) pushBuiltin(bundled)
          else push(bundled)
        }
        return
      }
      if (BUILTIN_MAP[entry]) {
        pushBuiltin(entry)
        return
      }
    }
    out.push(entry)
  }

  for (const entry of pluginConfigs || []) push(entry)
  return out
}
