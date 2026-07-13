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
    this._lifecycleTail = Promise.resolve()
    this._lifecyclePending = 0
    this._stopAllPending = 0
  }

  /**
   * Register a local service.
   * @param {ServiceProvider} provider - implements the ServiceProvider interface
   */
  register (provider) {
    if (this._lifecyclePending > 0) {
      const err = new Error('SERVICE_LIFECYCLE_BUSY: registration is closed during lifecycle mutation')
      err.code = 'SERVICE_LIFECYCLE_BUSY'
      throw err
    }
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

    const hasStart = overridesMethod(provider, 'start')
    const hasStop = overridesMethod(provider, 'stop')
    if (hasStart && !hasStop) {
      const err = new Error(`SERVICE_INVALID_LIFECYCLE: ${manifest.name} has start() without stop()`)
      err.code = 'SERVICE_INVALID_LIFECYCLE'
      throw err
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
      status: hasStart ? 'registered' : 'running',
      restartCount: 0,
      lastStartedAt: null,
      lastStoppedAt: null,
      lastError: null,
      context: null,
      _onProviderError: null,
      _hasStart: hasStart,
      _hasStop: hasStop
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
  unregister (name) {
    return this._queueLifecycle(() => this._unregister(name))
  }

  async _unregister (name) {
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
    if (this._lifecyclePending > 0) {
      throw new Error(`SERVICE_UNAVAILABLE: ${serviceName} lifecycle mutation pending`)
    }
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
  startAll (context) {
    return this._queueLifecycle(() => this._startAll(context))
  }

  async _startAll (context) {
    const started = []
    const failed = []
    let firstTeardownError = null

    // Keep startup atomic with respect to lifecycle safety. Even if a caller
    // mutates an entry after register(), never start any provider until every
    // start-capable provider has a matching teardown contract.
    for (const [name, entry] of this.services) {
      if (!entry._hasStart || entry._hasStop) continue
      entry.status = 'invalid-lifecycle'
      const error = new Error(`SERVICE_INVALID_LIFECYCLE: ${name} has start() without stop()`)
      error.code = 'SERVICE_INVALID_LIFECYCLE'
      throw error
    }

    for (const [name, entry] of this.services) {
      if (this._stopAllPending > 0) break
      if (entry._hasStart) {
        try {
          await entry.provider.start(context)
          if (this._stopAllPending > 0) {
            try {
              await entry.provider.stop()
              entry.status = 'stopped'
              entry.lastStoppedAt = Date.now()
            } catch (stopErr) {
              entry.status = 'start-stop-failed'
              entry.lastError = stopErr.message || String(stopErr)
              if (!firstTeardownError) firstTeardownError = stopErr
            }
            break
          }
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
          const failure = { name, error: err.message || String(err) }

          // start() may fail after opening cores, timers, sockets, or other
          // append-capable resources. Never discard that provider until its
          // matching stop() has settled. A failed stop keeps the entry in the
          // registry so startup rollback / a supervisor can retry teardown.
          if (entry._hasStop) {
            try {
              await entry.provider.stop()
              entry.status = 'stopped'
              entry.lastStoppedAt = Date.now()
            } catch (stopErr) {
              entry.status = 'start-stop-failed'
              entry.lastError = stopErr.message || String(stopErr)
              failure.stopError = entry.lastError
              this.emit('service-stop-error', { name, error: entry.lastError })
              if (!firstTeardownError) firstTeardownError = stopErr
            }
          }
          failed.push(failure)
        }
      } else {
        entry.status = 'running'
        entry.context = context
        entry.lastStartedAt = Date.now()
        started.push(name)
      }
    }

    // Fail closed: providers whose startup failure was fully settled are
    // removed so they cannot be dispatched. Unsettled providers stay owned.
    for (const failure of failed) {
      const entry = this.services.get(failure.name)
      if (!entry || entry.status === 'start-stop-failed') continue
      if (entry._onProviderError && typeof entry.provider.off === 'function') {
        entry.provider.off('error', entry._onProviderError)
      }
      this.services.delete(failure.name)
    }

    if (firstTeardownError) {
      const error = new Error('service provider startup teardown did not settle')
      error.code = 'SERVICE_START_TEARDOWN_FAILED'
      error.cause = firstTeardownError
      error.failed = failed
      throw error
    }

    return { started, failed }
  }

  /**
   * Stop all registered services.
   */
  stopAll (opts = {}) {
    this._stopAllPending++
    const operation = this._queueLifecycle(() => this._stopAll(opts))
    operation.then(
      () => { this._stopAllPending-- },
      () => { this._stopAllPending-- }
    )
    return operation
  }

  async _stopAll (opts = {}) {
    const throwOnError = opts.throwOnError === true
    let firstError = null
    for (const [name, entry] of this.services) {
      let stopped = true
      if (entry._hasStop && entry.status !== 'stopped' && entry.status !== 'registered') {
        try {
          await entry.provider.stop()
          entry.status = 'stopped'
          entry.lastStoppedAt = Date.now()
        } catch (err) {
          stopped = false
          entry.status = 'stop-failed'
          entry.lastError = err.message || String(err)
          this.emit('service-stop-error', { name, error: err.message })
          if (!firstError) firstError = err
        }
      }
      if (stopped && entry._onProviderError && typeof entry.provider.off === 'function') {
        entry.provider.off('error', entry._onProviderError)
      }
      if (stopped) this.services.delete(name)
    }
    if (!firstError) this.remoteServices.clear()
    if (firstError && throwOnError) {
      const failure = new Error('service provider teardown did not settle')
      failure.code = 'SERVICE_STOP_FAILED'
      failure.cause = firstError
      throw failure
    }
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

  restart (name, context = null) {
    return this._queueLifecycle(() => this._restart(name, context))
  }

  async _restart (name, context = null) {
    const entry = this.services.get(name)
    if (!entry) throw new Error(`SERVICE_NOT_FOUND: ${name}`)
    const serviceContext = context || entry.context || {}

    try {
      if (entry._hasStop) {
        await entry.provider.stop()
        entry.status = 'stopped'
        entry.lastStoppedAt = Date.now()
      }
    } catch (err) {
      entry.status = 'stop-failed'
      entry.lastError = err.message || String(err)
      this.emit('service-stop-error', { name, error: err.message || String(err) })
      const failure = new Error(`SERVICE_RESTART_STOP_FAILED: ${name}`)
      failure.code = 'SERVICE_RESTART_STOP_FAILED'
      failure.cause = err
      throw failure
    }

    if (this._stopAllPending > 0) {
      const failure = new Error(`SERVICE_RESTART_CANCELLED: ${name}`)
      failure.code = 'SERVICE_RESTART_CANCELLED'
      throw failure
    }

    try {
      if (entry._hasStart) await entry.provider.start(serviceContext)
      if (this._stopAllPending > 0) {
        try {
          if (entry._hasStop) await entry.provider.stop()
          entry.status = 'stopped'
          entry.lastStoppedAt = Date.now()
        } catch (teardownCause) {
          entry.status = 'stop-failed'
          entry.lastError = teardownCause.message || String(teardownCause)
          const failure = new Error(`SERVICE_RESTART_CANCEL_TEARDOWN_FAILED: ${name}`)
          failure.code = 'SERVICE_RESTART_CANCEL_TEARDOWN_FAILED'
          failure.teardownCause = teardownCause
          throw failure
        }
        const failure = new Error(`SERVICE_RESTART_CANCELLED: ${name}`)
        failure.code = 'SERVICE_RESTART_CANCELLED'
        throw failure
      }
      entry.status = 'running'
      entry.context = serviceContext
      entry.restartCount++
      entry.lastStartedAt = Date.now()
      entry.lastError = null
      this.emit('service-restarted', { name, restartCount: entry.restartCount })
      return entry
    } catch (err) {
      if (err?.code === 'SERVICE_RESTART_CANCELLED' ||
          err?.code === 'SERVICE_RESTART_CANCEL_TEARDOWN_FAILED') throw err
      entry.status = 'failed'
      entry.restartCount++
      entry.lastError = err.message || String(err)
      this.emit('service-restart-error', { name, error: entry.lastError, restartCount: entry.restartCount })
      if (!entry._hasStop) throw err
      try {
        await entry.provider.stop()
        entry.status = 'stopped'
        entry.lastStoppedAt = Date.now()
      } catch (teardownCause) {
        entry.status = 'restart-start-stop-failed'
        entry.lastError = teardownCause.message || String(teardownCause)
        this.emit('service-stop-error', { name, error: entry.lastError })
        const failure = new Error(`SERVICE_RESTART_START_TEARDOWN_FAILED: ${name}`)
        failure.code = 'SERVICE_RESTART_START_TEARDOWN_FAILED'
        failure.startCause = err
        failure.teardownCause = teardownCause
        throw failure
      }
      throw err
    }
  }

  _queueLifecycle (run) {
    this._lifecyclePending++
    const operation = this._lifecycleTail.catch(() => {}).then(run)
    const tail = operation.catch(() => {})
    this._lifecycleTail = tail
    operation.then(
      () => { this._lifecyclePending-- },
      () => { this._lifecyclePending-- }
    )
    return operation
  }
}
