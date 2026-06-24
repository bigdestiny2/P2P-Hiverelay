/**
 * Service Registry
 *
 * Manages the catalog of available services on a relay node.
 * Services are headless capabilities that apps consume — storage,
 * identity, payments, zk proofs, AI inference, etc.
 *
 * The registry handles:
 *   - Service registration and lifecycle
 *   - Capability advertisement to peers
 *   - Service discovery (local and remote)
 *   - Version negotiation
 *   - Usage metering (feeds into PaymentManager)
 */

import { EventEmitter } from 'events'
import { compareVersions } from '../constants.js'
import { sanitizeServiceCatalogEntries } from './service-catalog.js'

const BLOCKED_METHODS = new Set([
  'constructor', 'start', 'stop', 'manifest',
  'toString', 'valueOf', 'toJSON',
  'hasOwnProperty', 'isPrototypeOf'
])

function overridesMethod (provider, method) {
  if (!provider) return false
  if (Object.prototype.hasOwnProperty.call(provider, method)) return true
  const proto = provider ? Object.getPrototypeOf(provider) : null
  return !!proto && Object.prototype.hasOwnProperty.call(proto, method)
}

export class ServiceRegistry extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.services = new Map() // name -> ServiceEntry
    this.remoteServices = new Map() // relayPubkey -> [ServiceEntry]
    this.metering = opts.metering !== false
    this.maxServices = opts.maxServices || 64
  }

  /**
   * Register a local service.
   * @param {ServiceProvider} provider - implements the ServiceProvider interface
   */
  register (provider) {
    if (this.services.size >= this.maxServices) {
      throw new Error('SERVICE_LIMIT: max services reached')
    }

    const manifest = provider.manifest()
    if (!manifest.name || !manifest.version) {
      throw new Error('SERVICE_INVALID: manifest requires name and version')
    }

    if (this.services.has(manifest.name)) {
      throw new Error(`SERVICE_EXISTS: ${manifest.name} already registered`)
    }

    const entry = {
      name: manifest.name,
      version: manifest.version,
      capabilities: manifest.capabilities || [],
      description: manifest.description || '',
      provider,
      registeredAt: Date.now(),
      stats: {
        requests: 0,
        errors: 0,
        bytesIn: 0,
        bytesOut: 0
      },
      status: overridesMethod(provider, 'start') ? 'registered' : 'running',
      restartCount: 0,
      lastStartedAt: null,
      lastStoppedAt: null,
      lastError: null,
      context: null,
      _onProviderError: null,
      _hasStart: overridesMethod(provider, 'start'),
      _hasStop: overridesMethod(provider, 'stop')
    }

    if (provider && typeof provider.on === 'function') {
      entry._onProviderError = (err) => {
        this.markFailed(manifest.name, err)
      }
      provider.on('error', entry._onProviderError)
    }

    this.services.set(manifest.name, entry)
    this.emit('service-registered', { name: manifest.name, version: manifest.version })
    return entry
  }

  /**
   * Unregister a service.
   */
  async unregister (name) {
    const entry = this.services.get(name)
    if (!entry) return false

    if (entry._hasStop) {
      await entry.provider.stop()
    }

    if (entry._onProviderError && typeof entry.provider.off === 'function') {
      entry.provider.off('error', entry._onProviderError)
    }

    this.services.delete(name)
    this.emit('service-unregistered', { name })
    return true
  }

  /**
   * Handle an incoming RPC request for a service.
   */
  async handleRequest (serviceName, method, params, context) {
    const entry = this.services.get(serviceName)
    if (!entry) {
      throw new Error(`SERVICE_NOT_FOUND: ${serviceName}`)
    }

    if (entry.status && entry.status !== 'running') {
      throw new Error(`SERVICE_UNAVAILABLE: ${serviceName} status=${entry.status}`)
    }

    // Block dangerous/internal methods from RPC access
    if (BLOCKED_METHODS.has(method)) {
      throw new Error(`METHOD_BLOCKED: ${method}`)
    }

    if (!entry.provider[method] || typeof entry.provider[method] !== 'function') {
      throw new Error(`METHOD_NOT_FOUND: ${serviceName}.${method}`)
    }

    // Enforce capabilities: if the service defines them, only listed methods are callable
    if (entry.capabilities.length > 0 && !entry.capabilities.includes(method)) {
      throw new Error(`METHOD_NOT_ALLOWED: ${method} not in capabilities`)
    }

    entry.stats.requests++

    try {
      const result = await entry.provider[method](params, context)
      return result
    } catch (err) {
      entry.stats.errors++
      throw err
    }
  }

  /**
   * Record a remote relay's advertised services.
   */
  addRemoteServices (relayPubkey, services) {
    const sanitized = sanitizeServiceCatalogEntries(services)
    this.remoteServices.set(relayPubkey, {
      services: sanitized,
      lastSeen: Date.now()
    })
    this.emit('remote-services-updated', { relay: relayPubkey, count: sanitized.length })
  }

  /**
   * Find relays that provide a given service.
   */
  findProviders (serviceName, opts = {}) {
    const providers = []

    // Check local first
    const local = this.services.get(serviceName)
    if (local && local.status === 'running') {
      providers.push({
        relay: 'local',
        service: local,
        local: true
      })
    }

    // Check remote relays
    for (const [relay, info] of this.remoteServices) {
      const svc = info.services.find(s => s.name === serviceName)
      if (svc) {
        if (opts.minVersion && compareVersions(svc.version, opts.minVersion) < 0) continue
        providers.push({
          relay,
          service: svc,
          local: false,
          lastSeen: info.lastSeen
        })
      }
    }

    return providers
  }

  /**
   * Get the full service catalog (for advertising to peers).
   */
  catalog () {
    const entries = []
    for (const [name, entry] of this.services) {
      if (entry.status !== 'running') continue
      entries.push({
        name,
        version: entry.version,
        capabilities: entry.capabilities,
        description: entry.description
      })
    }
    return entries
  }

  /**
   * Get stats for all services.
   */
  stats () {
    const result = {}
    for (const [name, entry] of this.services) {
      result[name] = {
        ...entry.stats,
        status: entry.status,
        restartCount: entry.restartCount,
        lastError: entry.lastError
      }
    }
    return result
  }

  /**
   * Start all registered services.
   */
  async startAll (context) {
    const started = []
    const failed = []

    for (const [name, entry] of this.services) {
      if (entry._hasStart) {
        try {
          await entry.provider.start(context)
          entry.status = 'running'
          entry.context = context
          entry.lastStartedAt = Date.now()
          entry.lastError = null
          this.emit('service-started', { name })
          started.push(name)
        } catch (err) {
          entry.status = 'failed'
          entry.lastError = err.message || String(err)
          this.emit('service-start-error', { name, error: err.message })
          failed.push({ name, error: err.message })
        }
      } else {
        entry.status = 'running'
        entry.context = context
        entry.lastStartedAt = Date.now()
        started.push(name)
      }
    }

    // Fail closed: providers that failed startup are removed so they cannot be dispatched.
    for (const failure of failed) {
      this.services.delete(failure.name)
    }

    return { started, failed }
  }

  /**
   * Stop all registered services.
   */
  async stopAll () {
    for (const [name, entry] of this.services) {
      if (entry._hasStop) {
        try {
          await entry.provider.stop()
          entry.status = 'stopped'
          entry.lastStoppedAt = Date.now()
        } catch (err) {
          this.emit('service-stop-error', { name, error: err.message })
        }
      }
      if (entry._onProviderError && typeof entry.provider.off === 'function') {
        entry.provider.off('error', entry._onProviderError)
      }
    }
    this.services.clear()
    this.remoteServices.clear()
  }

  markFailed (name, err) {
    const entry = this.services.get(name)
    if (!entry) return false
    entry.status = 'failed'
    entry.lastError = err?.message || String(err || 'service failed')
    entry.failedAt = Date.now()
    this.emit('service-runtime-error', { name, error: entry.lastError })
    return true
  }

  async restart (name, context = null) {
    const entry = this.services.get(name)
    if (!entry) throw new Error(`SERVICE_NOT_FOUND: ${name}`)
    const serviceContext = context || entry.context || {}

    try {
      if (entry._hasStop) await entry.provider.stop()
    } catch (err) {
      this.emit('service-stop-error', { name, error: err.message || String(err) })
    }

    try {
      if (entry._hasStart) await entry.provider.start(serviceContext)
      entry.status = 'running'
      entry.context = serviceContext
      entry.restartCount++
      entry.lastStartedAt = Date.now()
      entry.lastError = null
      this.emit('service-restarted', { name, restartCount: entry.restartCount })
      return entry
    } catch (err) {
      entry.status = 'failed'
      entry.restartCount++
      entry.lastError = err.message || String(err)
      this.emit('service-restart-error', { name, error: entry.lastError, restartCount: entry.restartCount })
      throw err
    }
  }
}
