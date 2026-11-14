/**
 * BareRelay — Minimal Pear/Bare-native relay node
 *
 * This is a reduced RelayNode that runs under the Bare runtime (the JS
 * runtime behind Pear). It deliberately omits features that require
 * Node-only APIs:
 *
 *   - HTTP management API (node:http → would need bare-http1)
 *   - HTTP gateway (/v1/hyper/)
 *   - Compute service JS sandbox (node:vm, node:worker_threads)
 *   - AIService DNS-based SSRF check (node:dns)
 *   - Lightning payment provider (@grpc/grpc-js)
 *   - Interactive setup / manage TUI (@inquirer/prompts)
 *   - Tor transport (socks proxy lib is Node-only)
 *   - Pino logger (uses worker_threads)
 *
 * What it DOES provide:
 *
 *   - Hyperswarm DHT discovery + relay mesh
 *   - Corestore / Hyperdrive hosting
 *   - Seed protocol (accept, replicate, persist)
 *   - Circuit relay protocol (NAT traversal)
 *   - Service protocol channel (for RPC from clients)
 *   - Distributed-drive peer bridge (Ghost Drive compatibility)
 *   - App registry with typed content catalog
 *   - Catalog sync with other relays
 *
 * This is the minimum viable surface to participate in the HiveRelay mesh
 * as a seeding/relaying peer. Operators who want the management TUI and
 * HTTP dashboard run the Node version; operators who want auto-updates via
 * Pear and mobile/embedded support run this.
 *
 * Node and Bare relays interoperate over the DHT — they speak the same
 * Protomux protocols. A Pear-native relay and a Node relay can replicate
 * the same Hyperdrives and sync the same catalog without knowing (or
 * caring) which runtime the other one uses.
 */

import Hyperswarm from 'hyperswarm'
import {
  corestoreGenerationHealth,
  corestoreGenerationParticipantOptions,
  openCorestore
} from '../persistence/storage-root-restore.js'
import b4a from 'b4a'
import sodium from 'sodium-universal'
// Use Node-shaped names. Under Bare/Pear they get remapped via the
// package.json `imports` map to bare-events / bare-fs/promises / bare-path.
// Under Node they resolve to the built-ins. This lets the same source file
// import cleanly in both runtimes.
import { EventEmitter } from 'events'
import { readFile, writeFile, mkdir, chmod, rename, unlink, realpath } from 'fs/promises'
import { join } from 'path'

import { Seeder } from './seeder.js'
import { Relay } from './relay.js'
import { AppLifecycle } from './app-lifecycle.js'
import { LifecycleScope } from './lifecycle-scope.js'
import { SeedProtocol } from '../protocol/seed-request.js'
import { validateSeedDiscoveryHints } from '../protocol/seed-discovery-hints.js'
import { extractCustodySeedOpts } from '../seed-request-builder.js'
import { CircuitRelay } from '../protocol/relay-circuit.js'
import { ProofOfRelay } from '../protocol/proof-of-relay.js'
import { AppRegistry } from '../app-registry.js'
import { RELAY_DISCOVERY_TOPIC, FOUNDATION_TOPIC, DISCOVERY_EPOCH_MS, syncEpochDiscoveryTopics } from '../constants.js'
import { SwarmFirewall } from './swarm-firewall.js'

// Services framework lives in Core (p2p-hiverelay). Builtin service
// implementations live in p2p-hiveservices and are loaded dynamically below
// so a Bare operator who hasn't installed p2p-hiveservices still gets a
// working seeding/relaying node — just without service RPC.
import { ServiceRegistry } from '../services/registry.js'
import { ServiceProtocol } from '../services/protocol.js'

// Shared accept-mode helpers (also used by RelayNode).
import { resolveAcceptMode, decideAcceptance } from '../accept-mode.js'

// Device-attestation chain verification — same primitive the Node RelayNode
// uses in _scanRegistry. Lets a delegated device publish on behalf of its
// primary identity over the P2P seed-request protocol too, not just via the
// distributed registry path.
import { verifyDelegationCert, verifyRevocation } from '../delegation.js'

// Federation — opt-in cross-relay catalog sharing. Same module used by
// RelayNode; works under Bare via the package.json imports map remapping
// http → bare-http1 and fs/promises → bare-fs/promises.
import { Federation } from '../federation.js'

// Minimal HTTP surface — bare-http1
import { BareHttpServer } from './bare-http-server.js'
import {
  getStorageCapProvenance,
  markStorageCapDefault,
  markStorageCapExplicit,
  measureProvenStorageTreeBytes,
  positiveStorageBound,
  resolveStorageCap
} from '../../config/storage-cap.js'
import { StorageAdmissionAuthority } from '../../config/storage-admission-authority.js'
import { sharedOperationFlights } from '../shared-flight-registry.js'
import { strictPositiveInteger } from '../completion-scheduler.js'
import { AppCatalogController } from './app-catalog-controller.js'
import { AppCatalogDiskStageFactory } from './app-catalog-paged-stage.js'
import { APP_CATALOG_LIMITS } from './app-catalog-paged.js'
import { catalogRowToLegacyApp } from './app-catalog-source.js'

// Simple log helper — Bare has no pino, use plain console.
// Bare doesn't expose `process` as a global; guard env lookup.
const env = (typeof globalThis.process !== 'undefined' && globalThis.process.env) ||
            (typeof globalThis.Bare !== 'undefined' && globalThis.Bare.env) ||
            {}

function identityTempPath (keyPath) {
  const suffix = b4a.alloc(8)
  sodium.randombytes_buf(suffix)
  return keyPath + '.tmp-' + Date.now() + '-' + b4a.toString(suffix, 'hex')
}

// The shared shutdown deadline (_ownerDeadline) is a soft cap across ALL
// sequential teardown steps. Late steps would otherwise inherit only the
// crumbs left by earlier ones (observed in CI: "swarm.destroy timed out
// after 21ms" with zero real work attempted). Every owner-serialized
// operation gets at least this much of its own budget once it actually
// starts. Keep in sync with relay-node/index.js.
const MIN_OWNER_OPERATION_BUDGET_MS = 10_000
const BARE_RETIREMENT_POPULATION_CONSUMER = 'bare-shutdown'
const BARE_RETIREMENT_PAGE_BUDGET = 64
const BARE_RETIREMENT_MAX_PAGE_CALLS = 4_097
const BARE_RETIREMENT_MAX_WAVES = 8
const LEGACY_CATALOG_SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000
const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

function shuttingDownError (operation = 'runtime work') {
  const err = new Error(`${operation} rejected: BareRelay is shutting down`)
  err.code = 'SHUTTING_DOWN'
  return err
}

function withTimeout (promise, ms, label) {
  let timer
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => {
        const err = new Error(`${label} timed out after ${ms}ms`)
        err.code = 'OPERATION_TIMEOUT'
        reject(err)
      }, ms)
    })
  ])
}

const log = {
  info: (...a) => console.log('[info]', ...a),
  warn: (...a) => console.warn('[warn]', ...a),
  error: (...a) => console.error('[error]', ...a),
  debug: (...a) => env.HIVERELAY_DEBUG ? console.log('[debug]', ...a) : null
}

class BareServiceRegistry extends ServiceRegistry {
  constructor (opts = {}) {
    super(opts)
    this._bareAcceptingRequests = true
    this._bareRequests = new Set()
  }

  beginShutdown () {
    this._bareAcceptingRequests = false
  }

  handleRequest (...args) {
    if (!this._bareAcceptingRequests) return Promise.reject(shuttingDownError('service request'))
    const operation = Promise.resolve().then(() => super.handleRequest(...args))
    this._bareRequests.add(operation)
    const cleanup = () => this._bareRequests.delete(operation)
    operation.then(cleanup, cleanup)
    return operation
  }

  async drainRequests () {
    while (this._bareRequests.size > 0) {
      await Promise.allSettled([...this._bareRequests])
    }
  }
}

class BareServiceProtocol extends ServiceProtocol {
  constructor (...args) {
    super(...args)
    this._bareAcceptingRequests = true
    this._bareRequests = new Set()
  }

  beginShutdown () {
    this._bareAcceptingRequests = false
  }

  request (...args) {
    if (!this._bareAcceptingRequests) return Promise.reject(shuttingDownError('service protocol request'))
    return this._trackBareRequest(Promise.resolve().then(() => super.request(...args)))
  }

  _handleRequest (...args) {
    if (!this._bareAcceptingRequests) return Promise.resolve()
    // ServiceRegistry tracks provider settlement. Keep the outer protocol
    // chain too so shutdown also proves response/error publication completed.
    return this._trackBareRequest(Promise.resolve().then(() => super._handleRequest(...args)))
  }

  _trackBareRequest (operation) {
    this._bareRequests.add(operation)
    const cleanup = () => this._bareRequests.delete(operation)
    operation.then(cleanup, cleanup)
    return operation
  }

  async drainRequests () {
    while (this._bareRequests.size > 0) {
      await Promise.allSettled([...this._bareRequests])
    }
  }
}

const DEFAULT_CONFIG = {
  storage: './storage',
  hiverelayGeneration: null,
  enableRelay: true,
  enableSeeding: true,
  maxStorageBytes: 50 * 1024 * 1024 * 1024, // 50 GB
  maxConnections: 256,
  regions: ['NA'],
  httpPort: 9100,
  enableHttp: true,
  catalogSync: true,
  catalogMaxAppAgeMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  // Bare runtimes have no operator TUI, so the 'review' default would block
  // every inbound seed indefinitely. Default to 'open' here — Pear operators
  // who want a tighter posture can pass acceptMode: 'allowlist' or 'closed'.
  acceptMode: 'open',
  acceptAllowlist: [],
  appCatalogPaged: {
    sourceIntervalMs: 60_000,
    sourceBudget: 64,
    digestBudget: 128,
    sweepIntervalMs: 1_000,
    actionLimit: 10
  }
}

export class BareRelay extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (opts.appCatalogPaged != null) {
      const section = opts.appCatalogPaged
      const prototype = typeof section === 'object' ? Object.getPrototypeOf(section) : null
      if (typeof section !== 'object' || Array.isArray(section) ||
          (prototype !== Object.prototype && prototype !== null)) {
        throw new TypeError('appCatalogPaged must be a plain object')
      }
    }
    this._storagePathExplicit = Object.prototype.hasOwnProperty.call(opts, 'storage')
    this.config = {
      ...DEFAULT_CONFIG,
      ...opts,
      appCatalogPaged: {
        ...DEFAULT_CONFIG.appCatalogPaged,
        ...(opts.appCatalogPaged || {})
      }
    }
    this.config.appCatalogPaged.sourceIntervalMs = strictPositiveInteger(
      this.config.appCatalogPaged.sourceIntervalMs,
      'appCatalogPaged.sourceIntervalMs'
    )
    this.config.appCatalogPaged.sourceBudget = strictPositiveInteger(
      this.config.appCatalogPaged.sourceBudget,
      'appCatalogPaged.sourceBudget',
      64
    )
    this.config.appCatalogPaged.digestBudget = strictPositiveInteger(
      this.config.appCatalogPaged.digestBudget,
      'appCatalogPaged.digestBudget',
      128
    )
    this.config.appCatalogPaged.sweepIntervalMs = strictPositiveInteger(
      this.config.appCatalogPaged.sweepIntervalMs,
      'appCatalogPaged.sweepIntervalMs',
      30_000
    )
    this.config.appCatalogPaged.actionLimit = strictPositiveInteger(
      this.config.appCatalogPaged.actionLimit,
      'appCatalogPaged.actionLimit',
      10
    )
    if (Object.prototype.hasOwnProperty.call(opts, 'maxStorageBytes') && positiveStorageBound(opts.maxStorageBytes) === null) {
      throw new TypeError('maxStorageBytes must be a positive safe integer')
    }
    if (!getStorageCapProvenance(this.config)) {
      if (Object.prototype.hasOwnProperty.call(opts, 'maxStorageBytes')) markStorageCapExplicit(this.config, 'constructor')
      else markStorageCapDefault(this.config, positiveStorageBound(this.config.maxStorageBytes))
    }
    this.store = null
    this.swarm = null
    this.seeder = null
    this.relay = null
    this.appRegistry = null
    this.appCatalogController = null
    this.appCatalogStore = null
    this._appCatalogStageFactory = null
    this.appLifecycle = null
    this._seedProtocol = null
    this._circuitRelay = null
    this._proofOfRelay = null
    this._serviceProtocol = null
    this.serviceRegistry = null
    this._legacyCatalogAcceptedPeers = new Set()
    this._discovery = null
    this._foundationDiscovery = null
    this._regionDiscovery = null
    this._epochDiscoveryTimer = null
    this._epochDiscoveryTopics = new Map()
    this._retiringEpochDiscoveryHandles = new Set()
    this.federation = null
    // BareRelay has no operator TUI for the review queue; we still expose
    // the same `_pendingRequests` map for symmetry with RelayNode so any
    // Federation poll that produces 'queue' decisions has somewhere to put
    // them. In practice Bare operators run with acceptMode 'open' or 'allowlist'.
    this._pendingRequests = new Map()
    // Revoked delegation certs — same shape as RelayNode's. Index by cert
    // signature for O(1) lookup in _checkDelegation.
    this._revokedCertSignatures = new Map()
    this.connections = new Map() // Map<conn, { lastActivity }>
    this.running = false
    this.startedAt = null
    this._starting = false
    this._stopping = null
    this._ownerOperations = new WeakMap()
    this._ownerDeadline = null
    this._startCompletion = null
    this._lastStartCompletion = null
    this._stopRequested = false
    this._startupRollbackPending = false
    this._storageIngressReady = false
    this._scope = null
    // Runtime owners stay strongly reachable until their exact drain and
    // terminal close have both settled. Failed teardown therefore retries the
    // same object/generation instead of manufacturing a replacement owner.
    this._bareRuntimeOwners = new Map()
    this._shutdownFence = null
    this._shutdownGeneration = 0
    this._adoptBareRuntimeOwner(this, 'bareRelay')
    this.storageAdmission = new StorageAdmissionAuthority(this.config, {
      getUsedBytes: () => this._storageUsedBytes(),
      getActualBytes: (key) => this._storageActualBytes(key),
      recoveryKinds: ['drives', 'cores'],
      physicalEnforcer: this.config.physicalEnforcer || null
    })
  }

  // Symmetry with RelayNode so Federation can call it.
  _joinEpochDiscoveryTopics () {
    if (!this.swarm || this._shutdownFence) return
    this._epochDiscoveryTopics = syncEpochDiscoveryTopics(
      this._epochDiscoveryTopics,
      this.swarm,
      { server: true, client: false },
      null,
      DISCOVERY_EPOCH_MS,
      (handle) => this._queueEpochDiscoveryDestroy(handle)
    )
    for (const [key, handle] of this._epochDiscoveryTopics) {
      this._adoptBareRuntimeOwner(handle, `epochDiscovery:${key}`)
    }
  }

  _queueEpochDiscoveryDestroy (handle) {
    if (!handle || typeof handle.destroy !== 'function') return
    const entry = { handle, promise: null }
    this._retiringEpochDiscoveryHandles.add(entry)
    const run = this._retireBareRuntimeOwner(
      handle,
      'retiringEpochDiscovery.destroy',
      () => handle.destroy(),
      this.config.shutdownTimeoutMs || 30_000
    )
    entry.promise = run
    run.then(
      () => this._retiringEpochDiscoveryHandles.delete(entry),
      () => { entry.promise = null }
    )
  }

  async _destroyDiscoveryHandles (timeout) {
    let firstError = null
    const destroy = async (handle, label, terminal = null) => {
      if (!handle) return
      await this._retireBareRuntimeOwner(
        handle,
        label,
        terminal || (typeof handle.destroy === 'function' ? () => handle.destroy() : async () => {}),
        timeout
      )
    }
    for (const entry of [...this._retiringEpochDiscoveryHandles]) {
      try {
        if (entry.promise) {
          await this._retireBareRuntimeOwner(
            entry.handle,
            'retiringEpochDiscovery.destroy',
            () => entry.promise,
            timeout
          )
        } else {
          await destroy(entry.handle, 'retiringEpochDiscovery.destroy')
        }
        this._retiringEpochDiscoveryHandles.delete(entry)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    for (const [key, handle] of this._epochDiscoveryTopics) {
      try {
        await destroy(handle, `epochDiscovery(${key.slice(0, 8)}).destroy`)
        this._epochDiscoveryTopics.delete(key)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    for (const [field, label] of [
      ['_foundationDiscovery', 'foundationDiscovery.destroy'],
      ['_regionDiscovery', 'regionDiscovery.destroy'],
      ['_discovery', 'relayDiscovery.destroy']
    ]) {
      if (!this[field]) continue
      const handle = this[field]
      try {
        await destroy(handle, label)
        if (this[field] === handle) this[field] = null
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  _resolveAcceptMode () { return resolveAcceptMode(this.config) }
  _decideAcceptance (req, mode) { return decideAcceptance(req, mode, this.config.acceptAllowlist || []) }

  _emitSafely (event, ...args) {
    let firstError = null
    for (const listener of this.rawListeners(event)) {
      try { listener.apply(this, args) } catch (err) { if (!firstError) firstError = err }
    }
    if (firstError && event !== 'observer-error') {
      for (const listener of this.rawListeners('observer-error')) {
        try { listener.call(this, { event, error: firstError }) } catch (_) {}
      }
    }
    return this.listenerCount(event) > 0
  }

  _storageUsedBytes () {
    try { return measureProvenStorageTreeBytes(this.config) } catch (_) { return NaN }
  }

  _storageActualBytes (key) {
    if (typeof key !== 'string' || !key.startsWith('core:') || !this.seeder) return 0
    const entry = this.seeder.cores.get(key.slice('core:'.length))
    return Number.isSafeInteger(entry?.bytesStored) && entry.bytesStored >= 0 ? entry.bytesStored : 0
  }

  _cachedStorageRejection (additionalBytes = 0, opts = {}) {
    if (!this.storageAdmission || typeof this.storageAdmission.cachedRejection !== 'function') {
      return { reject: true, exactRequired: false, reason: 'storage-admission-unavailable', informationalAvailableBytes: 0 }
    }
    return this.storageAdmission.cachedRejection(additionalBytes, { ...opts, storageSummary: null })
  }

  _informationalAvailableStorageBytes () {
    const hint = this._cachedStorageRejection(0)
    return Number.isSafeInteger(hint.informationalAvailableBytes) && hint.informationalAvailableBytes >= 0
      ? hint.informationalAvailableBytes
      : 0
  }

  async _startAppCatalogController () {
    if (this.appCatalogController && !this.appCatalogController.stopped) {
      return this.appCatalogController.start()
    }
    const canonicalStorage = await realpath(this.config.storage)
    const stageFactory = new AppCatalogDiskStageFactory({
      rootDir: join(canonicalStorage, 'app-catalog-paged')
    })
    const catalogConfig = this.config.appCatalogPaged
    const controller = new AppCatalogController({
      appRegistry: this.appRegistry,
      keyPair: this.swarm.keyPair,
      stageFactory,
      sourceIntervalMs: catalogConfig.sourceIntervalMs,
      sourceBudget: catalogConfig.sourceBudget,
      digestBudget: catalogConfig.digestBudget,
      sweepIntervalMs: catalogConfig.sweepIntervalMs,
      actionLimit: catalogConfig.actionLimit,
      onCatalogComplete: completed => this._emitSafely('app-catalog-paged', {
        peerPubkey: completed.peerPubkey,
        snapshotId: completed.snapshot.snapshotId,
        highWater: completed.snapshot.highWater,
        entryCount: completed.snapshot.entryCount
      }),
      onCatalogActionPage: action => this._applyPagedCatalogAction(action),
      onLegacyFallback: event => this._emitSafely('catalog-legacy-fallback', event),
      onError: event => this._emitSafely('catalog-paged-error', {
        phase: event.phase,
        peer: event.peer,
        error: event.error?.message || String(event.error)
      })
    })
    this._appCatalogStageFactory = stageFactory
    this.appCatalogController = controller
    this.appCatalogStore = controller.store
    this._adoptBareStartupOwner(controller, 'appCatalogController')
    return controller.start()
  }

  _startCoreServiceProtocol () {
    if (this._serviceProtocol && this.serviceRegistry) return this._serviceProtocol
    if (this._serviceProtocol || this.serviceRegistry) {
      throw new Error('Bare core service protocol ownership is inconsistent')
    }
    this.serviceRegistry = new BareServiceRegistry()
    this._adoptBareStartupOwner(this.serviceRegistry, 'serviceRegistry')
    this._serviceProtocol = new BareServiceProtocol(this.serviceRegistry, {
      defaultPeerRole: (this.config && this.config.serviceDefaultPeerRole) || 'anonymous',
      scheduleLegacyAppCatalog: request => this._scheduleLegacyAppCatalog(request)
    })
    this._serviceProtocol.on('app-catalog', envelope => this._handleLegacyAppCatalog(envelope))
    this._serviceProtocol.on('channel-close', ({ remotePubkey }) => {
      this._legacyCatalogAcceptedPeers?.delete(remotePubkey)
    })
    this._adoptBareStartupOwner(this._serviceProtocol, 'serviceProtocol')
    return this._serviceProtocol
  }

  _openStorageIngress () {
    if (!this.appCatalogController || !this._serviceProtocol) {
      const err = new Error('Bare catalog transports must exist before storage ingress opens')
      err.code = 'CATALOG_INGRESS_PROTOCOLS_NOT_READY'
      throw err
    }
    this._storageIngressReady = true
    this.swarm.on('connection', (conn, info) => this._onConnection(conn, info))
  }

  _scheduleLegacyAppCatalog ({ remotePubkey, send }) {
    const controller = this.appCatalogController
    if (this._stopRequested || !this._storageIngressReady || this._shutdownFence ||
        !controller || controller.stopped || typeof send !== 'function') return null
    const scheduled = controller.scheduleLegacyFallback(remotePubkey, () => {
      return send(controller.legacyEnvelope())
    })
    if (!scheduled) return null
    return () => controller.cancelLegacyFallback(remotePubkey)
  }

  _handleLegacyAppCatalog (envelope) {
    const peer = envelope?.remotePubkey
    const acceptedPeers = this._legacyCatalogAcceptedPeers instanceof Set
      ? this._legacyCatalogAcceptedPeers
      : (this._legacyCatalogAcceptedPeers = new Set())
    if (this._shutdownFence || this._stopRequested || !this._storageIngressReady ||
        !this.config.catalogSync || !this.config.enableSeeding ||
        acceptedPeers.has(peer) ||
        acceptedPeers.size >= APP_CATALOG_LIMITS.maxInboundPeers ||
        !this._verifyLegacyCatalogEnvelope(envelope)) {
      if (!this._shutdownFence && !this._stopRequested && this._storageIngressReady) {
        this._emitSafely('catalog-sync-error', {
          source: envelope?.remotePubkey || null,
          error: 'invalid, stale, or overbound legacy catalog'
        })
      }
      return false
    }
    // A legacy services channel owns at most one complete type-7 catalog.
    // ServiceProtocol's exact channel-close callback releases this peer token;
    // unique-peer churn therefore cannot retain more than the channel cap.
    acceptedPeers.add(peer)
    const operation = this._applyCatalogActions({
      apps: envelope.apps,
      maxActions: 10
    }).catch(err => {
      this._emitSafely('catalog-sync-error', {
        source: envelope.remotePubkey,
        error: err?.message || String(err)
      })
    })
    // Service shutdown drains this exact inbound action chain before closing
    // the channel/registry owners. The handler's synchronous fence above
    // prevents a post-shutdown chain from ever being admitted.
    this._serviceProtocol?._trackBareRequest?.(operation)
    return true
  }

  _verifyLegacyCatalogEnvelope (envelope) {
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
        envelope.delta === true || !Array.isArray(envelope.apps) ||
        envelope.apps.length > APP_CATALOG_LIMITS.maxLegacyEntries ||
        !HEX_64.test(envelope.remotePubkey) ||
        envelope.relayPubkey !== envelope.remotePubkey ||
        !HEX_64.test(envelope.relayPubkey) ||
        !Number.isSafeInteger(envelope.catalogTimestamp) || envelope.catalogTimestamp <= 0 ||
        !HEX_128.test(envelope.signature)) return false
    const maxAgeMs = Number.isSafeInteger(this.config.catalogSignatureMaxAgeMs) &&
      this.config.catalogSignatureMaxAgeMs > 0
      ? this.config.catalogSignatureMaxAgeMs
      : LEGACY_CATALOG_SIGNATURE_MAX_AGE_MS
    if (Math.abs(Date.now() - envelope.catalogTimestamp) > maxAgeMs) return false
    try {
      const wire = {
        type: 7,
        apps: envelope.apps,
        relayPubkey: envelope.relayPubkey,
        catalogTimestamp: envelope.catalogTimestamp,
        signature: envelope.signature
      }
      if (b4a.byteLength(JSON.stringify(wire), 'utf8') > APP_CATALOG_LIMITS.maxPayloadBytes) return false
      const signable = b4a.from(JSON.stringify({
        apps: envelope.apps,
        relayPubkey: envelope.relayPubkey,
        catalogTimestamp: envelope.catalogTimestamp
      }), 'utf8')
      return sodium.crypto_sign_verify_detached(
        b4a.from(envelope.signature, 'hex'),
        signable,
        b4a.from(envelope.remotePubkey, 'hex')
      )
    } catch {
      return false
    }
  }

  async _applyPagedCatalogAction (action) {
    if (this._shutdownFence || this._stopRequested || !this._storageIngressReady ||
        !this.config.enableSeeding) return { acted: 0, stop: true }
    const apps = []
    for (const row of action.entries) apps.push(catalogRowToLegacyApp(row))
    return this._applyCatalogActions({
      apps,
      maxActions: action.remainingActions
    })
  }

  async _applyCatalogActions ({ apps, maxActions = 10 }) {
    if (this._shutdownFence || this._stopRequested || !this._storageIngressReady ||
        !this.config.enableSeeding || !Array.isArray(apps)) return { acted: 0, stop: true }
    const actionLimit = strictPositiveInteger(
      Math.min(maxActions, 10),
      'catalog action limit',
      10
    )
    let acted = 0
    let mode = this._resolveAcceptMode()
    if (mode === 'review') mode = 'closed'
    for (const app of apps) {
      if (this._shutdownFence || this._stopRequested ||
          !this._storageIngressReady || acted >= actionLimit) break
      const appKey = app.appKey
      if (!appKey) continue
      const existing = this.appRegistry.get(appKey)
      // Bare has no reputation authority equivalent to the Node runtime's
      // explicit follow-anchored policy. An authenticated peer is not by
      // itself trusted to induce repair I/O for an existing local app.
      if (existing) continue
      // Both paged and legacy catalogs authenticate a relay's testimony, not
      // a publisher's authorization for this drive. Publisher allowlists must
      // be satisfied through the signed seed-request path instead.
      if (mode === 'allowlist') {
        this._emitSafely('catalog-sync-rejected', {
          appKey,
          source: 'remote-catalog',
          mode,
          reason: 'publisher-authorization-required'
        })
        continue
      }
      const maxStorageBytes = positiveStorageBound(app.maxStorageBytes)
      if (maxStorageBytes === null) {
        this._emitSafely('catalog-sync-rejected', {
          appKey,
          source: 'remote-catalog',
          reason: 'storage-bound-invalid'
        })
        continue
      }
      if (app.seededAt && this.config.catalogMaxAppAgeMs > 0 &&
          (Date.now() - app.seededAt) > this.config.catalogMaxAppAgeMs) continue
      const request = {
        appKey,
        publisherPubkey: null,
        contentType: app.type,
        privacyTier: app.privacyTier,
        blind: app.blind,
        storageClass: app.storageClass,
        availabilityClass: app.availabilityClass,
        maxStorageBytes
      }
      if (this._decideAcceptance(request, mode) !== 'accept') {
        this._emitSafely('catalog-sync-rejected', { appKey, source: 'remote-catalog', mode })
        continue
      }
      acted++
      try {
        await this.seedApp(appKey, {
          appId: app.appId,
          version: app.version,
          type: app.type,
          parentKey: app.parentKey,
          mountPath: app.mountPath,
          privacyTier: app.privacyTier,
          blind: app.blind,
          storageClass: app.storageClass,
          availabilityClass: app.availabilityClass,
          // Open acceptance permits discovery-based storage, but the catalog
          // claim must not become a locally attributed publisher identity.
          publisherPubkey: null,
          maxStorage: maxStorageBytes
        })
        this._emitSafely('catalog-sync', { appKey, source: 'remote-catalog', mode })
      } catch (err) {
        this._emitSafely('catalog-sync-error', { appKey, error: err.message || String(err) })
      }
    }
    return { acted, stop: acted >= actionLimit }
  }

  get publicKey () { return this.swarm ? this.swarm.keyPair.publicKey : null }
  get seededApps () { return this.appRegistry ? this.appRegistry.apps : new Map() }
  getStorageGenerationStatus () {
    return corestoreGenerationHealth(this.config.hiverelayGeneration, this.store)
  }

  seedApp (appKey, opts) {
    this._assertBareWorkAccepted('seedApp')
    return this.appLifecycle.seedApp(appKey, opts)
  }

  unseedApp (appKey, opts) {
    this._assertBareWorkAccepted('unseedApp')
    return this.appLifecycle.unseedApp(appKey, opts)
  }

  // The Node RelayNode sets this.keyPair; Bare only has this.swarm.keyPair.
  // Alias it so services that sign with the relay identity (e.g. storage-proof)
  // work identically on both runtimes.
  get keyPair () { return this.swarm ? this.swarm.keyPair : null }

  start () {
    if (this._startCompletion) return this._startCompletion
    if (this._startupRollbackPending) {
      const err = new Error('startup rollback is still pending storage mutation settlement')
      err.code = 'STORAGE_STARTUP_ROLLBACK_PENDING'
      return Promise.reject(err)
    }
    if (this._shutdownFence && this._shutdownFence.state !== 'COMPLETE') {
      return Promise.reject(shuttingDownError('start'))
    }
    if (!this._stopping && this.running) {
      if (!this._lastStartCompletion) this._lastStartCompletion = Promise.resolve(this)
      return this._lastStartCompletion
    }

    this._starting = true
    const operation = this._startLifecycle()
    this._startCompletion = operation
    operation.then(
      value => {
        if (this._startCompletion !== operation) return
        this._startCompletion = null
        this._starting = false
        if (value === this && this.running) this._lastStartCompletion = operation
      },
      () => {
        if (this._startCompletion !== operation) return
        this._startCompletion = null
        this._starting = false
      }
    )
    return operation
  }

  async _startLifecycle () {
    if (this._stopping) await this._stopping
    if (this.running) return this
    if (this._startupRollbackPending) {
      const err = new Error('startup rollback is still pending storage mutation settlement')
      err.code = 'STORAGE_STARTUP_ROLLBACK_PENDING'
      throw err
    }
    if (this._shutdownFence) {
      if (this._shutdownFence.state !== 'COMPLETE') throw shuttingDownError('start')
      this._resetBareRuntimeCycle()
    }
    this._stopRequested = false
    this._storageIngressReady = false
    this._scope = new LifecycleScope()

    try {
      log.info('BareRelay starting…')
      log.info('  storage:', this.config.storage)

      // Only the built-in relative default may be created automatically;
      // custom paths must pre-exist so a missing mount fails closed.
      if (!this._storagePathExplicit) await mkdir(this.config.storage, { recursive: true })
      this._assertBareWorkAccepted('start')
      resolveStorageCap(this.config)
      const storageProof = getStorageCapProvenance(this.config)
      if (!storageProof || storageProof.status !== 'resolved') {
        const err = new Error('configured storage filesystem is unresolved: ' + (storageProof?.reason || 'unknown'))
        err.code = 'STORAGE_FILESYSTEM_UNRESOLVED'
        throw err
      }
      this.storageAdmission.setConfig(this.config)
      this.storageAdmission.beginRecovery(['drives', 'cores'])
      this.storageAdmission.refreshFilesystem()
      await this.storageAdmission.activatePhysicalEnforcement({ purpose: 'bare-relay-startup' })
      this._assertBareWorkAccepted('start')

      // 1. Corestore — persistent hypercore storage.
      // openCorestore, not `new Corestore`: Corestore 7 sweeps every
      // unrecognised top-level entry of a pre-7 root into db/ *inside its
      // constructor*, which would strand app-registry.json and evicted.json
      // before load() below can migrate them. See storage-root-restore.js.
      this.store = openCorestore(
        this.config.storage,
        corestoreGenerationParticipantOptions(this.config.hiverelayGeneration, 'bare-relay')
      )
      this._adoptBareStartupOwner(this.store, 'corestore')
      await this.store.ready()
      this._assertBareWorkAccepted('start')

      // 2. App registry — tracks what we're seeding.
      // AppRegistry takes a storage *directory*, not a full file path.
      // v0.8.25: also pass the corestore so persistence uses a Hyperbee
      // sibling-core instead of the JSON-blob file. setStore() must be
      // called BEFORE load() — load() does one-time JSON→bee migration
      // on first boot if app-registry.json exists.
      this.appRegistry = new AppRegistry(this.config.storage, {
        storageAdmission: this.storageAdmission,
        requirePhysicalEnforcement: this.config.requirePhysicalEnforcement === true ||
          !!this.config.physicalEnforcer
      })
      this._adoptBareStartupOwner(this.appRegistry, 'appRegistry')
      this.appRegistry.setStore(this.store)
      await this.appRegistry.load()
      this._assertBareWorkAccepted('start')

      // 3. Connection-layer firewall — runs before Noise handshake. Cheapest
      //    DoS defense available. See packages/core/core/relay-node/swarm-firewall.js
      this.swarmFirewall = new SwarmFirewall({
        allowlist: this.config.swarmAllowlist || [],
        blocklist: this.config.swarmBlocklist || [],
        ipMaxConnects: this.config.swarmIpMaxConnects ?? 100,
        ipWindowMs: this.config.swarmIpWindowMs ?? 60_000,
        minReputation: this.config.swarmMinReputation ?? -1000,
        onReject: ({ reason, pubkey, ip }) => {
          log.debug('  ⊘ firewall:', reason, pubkey ? pubkey.slice(0, 16) : '?')
        }
      })

      // 4. Hyperswarm — DHT + peer connections
      this.swarm = new Hyperswarm({
        maxPeers: this.config.maxConnections,
        keyPair: await this._deriveKeypair(),
        firewall: (remotePubKey, payload) => this.swarmFirewall.check(remotePubKey, payload)
      })
      this._adoptBareStartupOwner(this.swarm, 'swarm')

      // 4. Seeder — pulls and keeps hypercores replicating
      this.seeder = new Seeder(this.store, this.swarm, {
        maxStorageBytes: this.config.maxStorageBytes,
        storageAdmission: this.storageAdmission,
        storagePath: join(this.config.storage, 'seeded-cores.json')
      })
      this._adoptBareStartupOwner(this.seeder, 'seeder')
      await this.seeder.start()
      this._assertBareWorkAccepted('start')

      // 5. Relay for circuit traversal (optional)
      if (this.config.enableRelay) {
        this.relay = new Relay(this.swarm, {
          maxCircuits: 256,
          maxBandwidthMbps: 100
        })
        this._adoptBareStartupOwner(this.relay, 'relay')
      }

      // 6. Protocol handlers — these attach to every incoming connection.
      // SeedProtocol has signature (swarm, opts); event-driven API.
      this._seedProtocol = new SeedProtocol(this.swarm, { keyPair: this.swarm.keyPair })
      this._adoptBareStartupOwner(this._seedProtocol, 'seedProtocol')
      this._seedProtocol.on('seed-request', (msg, channel) => {
        this._onSeedRequest(msg, channel).catch((err) => this.emit('seed-error', { error: err }))
      })
      this._seedProtocol.on('unseed-request', (msg) => this._onUnseedRequest(msg))

      this._circuitRelay = this.relay
        ? new CircuitRelay(this.relay)
        : null
      this._adoptBareStartupOwner(this._circuitRelay, 'circuitRelay')
      this._proofOfRelay = new ProofOfRelay(this.swarm.keyPair)
      this._adoptBareStartupOwner(this._proofOfRelay, 'proofOfRelay')

      // 7. App lifecycle — seed/unseed/index operations
      this.appLifecycle = new AppLifecycle(this)
      this._adoptBareStartupOwner(this.appLifecycle, 'appLifecycle')
      // Core inventory sealed in Seeder.start(); seal the drive inventory before
      // any storage-producing service provider is constructed or started.
      const reseedEntries = await this.appLifecycle.loadRegistry()
      this._assertBareWorkAccepted('start')
      if (!this.storageAdmission.recoveryReady) {
        const err = new Error('storage recovery inventories did not seal before writable services')
        err.code = 'STORAGE_RECOVERY_INVENTORY_INCOMPLETE'
        throw err
      }
      await this._startAppCatalogController()
      this._assertBareWorkAccepted('start')
      this._startCoreServiceProtocol()
      this._openStorageIngress()

      // 8. Services layer — Bare-safe subset.
      //
      // We dynamic-import each builtin from p2p-hiveservices so that:
      //   - operators who only install Core get a clean "no services" mode
      //   - Compute and AI builtins, which need Node-only deps (vm / dns), are
      //     simply not in the list below
      if (this.config.enableServices !== false) {
        const bareSafeServices = [
          { name: 'identity', module: 'p2p-hiveservices/builtin/identity-service.js', className: 'IdentityService', opts: { keyPair: this.swarm.keyPair } },
          { name: 'storage', module: 'p2p-hiveservices/builtin/storage-service.js', className: 'StorageService', opts: { store: this.store } },
          { name: 'schema', module: 'p2p-hiveservices/builtin/schema-service.js', className: 'SchemaService' },
          { name: 'sla', module: 'p2p-hiveservices/builtin/sla-service.js', className: 'SLAService', opts: { maxContracts: 1000 } },
          { name: 'arbitration', module: 'p2p-hiveservices/builtin/arbitration-service.js', className: 'ArbitrationService' },
          { name: 'zk', module: 'p2p-hiveservices/builtin/zk-service.js', className: 'ZKService' },
          { name: 'vrf', module: 'p2p-hiveservices/builtin/vrf-service.js', className: 'VRFService', opts: { keyPair: this.swarm.keyPair, beacon: this.config.vrfBeacon } }
        ]

        // Poker is an APP-level service (card-blind signed-log substrate for
        // turn-based games), not relay infrastructure — so it is opt-in only:
        // register it when the operator selected it (setup checkbox → config.services
        // / config.plugins, or HIVERELAY_POKER=1). The module ships in
        // p2p-hiveservices but no relay registered it before, so poker tables were
        // unreachable on a stock node. PokerApp fits the generic registration loop
        // below (it reads context.node in start()). Tables are in-memory with a 24h
        // idle TTL; the durable hypercore mirror (persistence-hypercore.js) is a
        // follow-up that routes service-created tables through createPersistentTable.
        const appServices = this.config.services || this.config.plugins || []
        const pokerSelected = (Array.isArray(appServices) && appServices.includes('poker')) ||
        env.HIVERELAY_POKER === '1'
        if (pokerSelected) {
          bareSafeServices.push({ name: 'poker', module: 'p2p-hiveservices/builtin/poker/index.js', className: 'PokerApp' })
        }

        const outboxLogSelected = (Array.isArray(appServices) && appServices.includes('outboxlog')) ||
        env.HIVERELAY_OUTBOXLOG === '1'
        if (outboxLogSelected) {
          bareSafeServices.push({ name: 'outboxlog', module: 'p2p-hiveservices/builtin/outboxlog/index.js', className: 'OutboxLogApp' })
        }

        const notifySelected = (Array.isArray(appServices) && appServices.includes('notify')) ||
        env.HIVERELAY_NOTIFY === '1'
        if (notifySelected) {
          bareSafeServices.push({ name: 'notify', module: 'p2p-hiveservices/builtin/notify-service.js', className: 'NotifyService' })
        }

        // Storage-proof — Tier-2 trustless seed verification (signed proof that
        // this relay holds a seeded block). Opt-in like poker so a stock node
        // stays minimal; uses node.appRegistry + the relay identity (node.keyPair
        // aliased above). Self-guards blind/private drives + rate-limits.
        const storageProofSelected = (Array.isArray(appServices) && appServices.includes('storage-proof')) ||
        env.HIVERELAY_STORAGE_PROOF === '1'
        if (storageProofSelected) {
          bareSafeServices.push({
            name: 'storage-proof',
            module: 'p2p-hiveservices/builtin/storage-proof-service.js',
            className: 'StorageProofService'
          })
        }

        let registered = 0
        let servicesPackageMissing = false
        for (const spec of bareSafeServices) {
          let provider = null
          try {
            const mod = await import(spec.module)
            this._assertBareWorkAccepted('start')
            const Ctor = mod[spec.className]
            if (!Ctor) {
              log.warn('  service skipped (missing export):', spec.name)
              continue
            }
            provider = new Ctor(spec.opts || {})
            this._adoptBareStartupOwner(provider, `service:${spec.name}`)
            this.serviceRegistry.register(provider)
            registered++
          } catch (err) {
            if (provider) {
              try {
                await this._retireBareRuntimeOwner(
                  provider,
                  `service:${spec.name}`,
                  typeof provider.stop === 'function'
                    ? () => provider.stop()
                    : (typeof provider.destroy === 'function' ? () => provider.destroy() : async () => {}),
                  this.config.shutdownTimeoutMs || 30_000
                )
              } catch (teardownErr) {
                const failure = new Error(`Bare service ${spec.name} registration teardown did not settle`)
                failure.code = 'BARE_SERVICE_REGISTRATION_TEARDOWN_FAILED'
                failure.startCause = err
                failure.teardownCause = teardownErr
                throw failure
              }
            }
            if (err?.code === 'SHUTTING_DOWN') throw err
            // First-time MODULE_NOT_FOUND on the whole package → skip rest quietly.
            if (err.code === 'ERR_MODULE_NOT_FOUND' && err.message.includes('p2p-hiveservices')) {
              servicesPackageMissing = true
              break
            }
            log.warn('  service start failed:', spec.name, '-', err.message)
          }
        }

        if (servicesPackageMissing) {
          log.info('  services: p2p-hiveservices not installed — running Core-only')
        } else {
          const startup = await this.serviceRegistry.startAll({ node: this, store: this.store })
          this._assertBareWorkAccepted('start')
          registered = startup.started.length
          for (const failure of startup.failed) {
            log.warn('  service start failed:', failure.name, '-', failure.error)
          }
          log.info('  services:', registered, 'registered')
        }
      }

      // 9. Optional minimal HTTP server (bare-http1) — read-only endpoints
      if (this.config.enableHttp !== false) {
        this.httpServer = new BareHttpServer(this, {
          port: this.config.httpPort,
          host: this.config.httpHost || '0.0.0.0'
        })
        this._adoptBareStartupOwner(this.httpServer, 'httpServer')
        try {
          const { port } = await this.httpServer.start()
          this._assertBareWorkAccepted('start')
          log.info('  http: http://127.0.0.1:' + port + '/status')
        } catch (startErr) {
          const server = this.httpServer
          try {
            await this._retireBareRuntimeOwner(
              server,
              'httpServer',
              () => server.stop(),
              this.config.shutdownTimeoutMs || 30_000
            )
            if (this.httpServer === server) this.httpServer = null
          } catch (teardownErr) {
            const failure = new Error('bare HTTP startup teardown did not settle')
            failure.code = 'BARE_HTTP_START_TEARDOWN_FAILED'
            failure.startCause = startErr
            failure.teardownCause = teardownErr
            throw failure
          }
          if (startErr?.code === 'SHUTTING_DOWN') throw startErr
          log.warn('  http start failed (continuing without):', startErr.message)
        }
      }

      // 10. Announce on the global discovery topic. Foundation relays opt-in
      //    via config.foundation = true. Region-sharded topics are available
      //    via regionTopic(code) but not auto-joined — premature at <10 relays.
      // Epoch-rotated discovery (opt-in via config.privacy.rotateDiscoveryTopic):
      // mirrors the Node relay (relay-node/index.js). 'additive' keeps the static
      // topic; 'strict' drops it. Default (off) is unchanged behaviour.
      const rotateMode = this.config.privacy && this.config.privacy.rotateDiscoveryTopic
      if (rotateMode !== 'strict') {
        this._discovery = this.swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: true })
        this._adoptBareStartupOwner(this._discovery, 'relayDiscovery')
      }
      if (rotateMode === 'additive' || rotateMode === 'strict') {
        this._joinEpochDiscoveryTopics()
        this._epochDiscoveryTimer = setInterval(
          () => { try { this._joinEpochDiscoveryTopics() } catch (_) {} },
          Math.max(60_000, Math.floor(DISCOVERY_EPOCH_MS / 2))
        )
        if (this._epochDiscoveryTimer.unref) this._epochDiscoveryTimer.unref()
      }
      if (this.config.foundation === true) {
        this._foundationDiscovery = this.swarm.join(FOUNDATION_TOPIC, { server: true, client: false })
        this._adoptBareStartupOwner(this._foundationDiscovery, 'foundationDiscovery')
      }

      // 11. Federation — opt-in cross-relay catalog sharing. Always-on as a
      // manager so a Pear app could expose follow/mirror controls in its UI;
      // the polling loop only runs if the operator has actually followed
      // any relays. Storage co-located with the rest of the Bare relay state.
      this.federation = new Federation({
        node: this,
        followInterval: this.config.federation?.followInterval,
        followed: this.config.federation?.followed || [],
        mirrored: this.config.federation?.mirrored || [],
        republished: this.config.federation?.republished || [],
        trustedForkObservers: this.config.federation?.trustedForkObservers || [],
        storagePath: join(this.config.storage, 'federation.json')
      })
      this._adoptBareStartupOwner(this.federation, 'federation')
      try { await this.federation.load() } catch (err) { log.warn('  federation load failed:', err.message) }
      this._assertBareWorkAccepted('start')
      if (this.config.federation?.enabled !== false) {
        this.federation.start()
      }

      // Bound flush — don't hang indefinitely if no peers
      await Promise.race([
        this.swarm.flush().catch(() => {}),
        new Promise(resolve => {
          const t = setTimeout(resolve, 2000)
          if (t.unref) t.unref()
        })
      ])
      this._assertBareWorkAccepted('start')

      // 9. Replay any previously-seeded apps from the registry
      if (this.config.enableSeeding) {
        await this.appLifecycle.reseedDrives(reseedEntries)
        this._assertBareWorkAccepted('start')
      }

      if (this._stopRequested) throw new Error('START_CANCELLED_BY_STOP')
      this.running = true
      this.startedAt = Date.now()

      const pkHex = b4a.toString(this.swarm.keyPair.publicKey, 'hex')
      log.info('  pubkey:', pkHex)
      log.info('  topic:', b4a.toString(RELAY_DISCOVERY_TOPIC, 'hex').slice(0, 16) + '…')
      log.info('  seeded apps:', this.appRegistry.apps.size)
      log.info('BareRelay running. Press Ctrl+C to stop.')

      this._emitSafely('started', { publicKey: this.swarm.keyPair.publicKey })
      return this
    } catch (err) {
      let failure = err
      this._ownerDeadline = Date.now() + (this.config.shutdownTimeoutMs || 30_000)
      try {
        await this._rollbackFailedStart()
      } catch (rollbackErr) {
        rollbackErr.cause = err
        failure = rollbackErr
        // Any incomplete rollback retains live owner records, not only storage
        // mutation timeouts. Keep the retry gate closed until those exact
        // owners settle in a later stop/rollback wave.
        this._startupRollbackPending = true
      } finally {
        this._ownerDeadline = null
      }
      throw failure
    }
  }

  async _rollbackFailedStart () {
    this._installBareShutdownFence('startup-rollback')
    const timeout = this.config.shutdownTimeoutMs || 30_000
    let writerQuiesceError = null
    const settleWriter = async (run) => {
      try { await run() } catch (err) { if (!writerQuiesceError) writerQuiesceError = err }
    }
    if (this._epochDiscoveryTimer) { clearInterval(this._epochDiscoveryTimer); this._epochDiscoveryTimer = null }
    await settleWriter(() => this._retireBareField('httpServer', 'httpServer', server => server.stop(), timeout))
    await settleWriter(() => this._retireBareField(
      'appCatalogController',
      'appCatalogController',
      value => value.stop(),
      timeout
    ))
    this.appCatalogStore = null
    this._appCatalogStageFactory = null
    await settleWriter(() => this._stopBareServiceIngress(timeout))
    await settleWriter(() => this._destroyProtocolHandlers(timeout))
    await settleWriter(() => this._stopBareServices(timeout))
    await settleWriter(() => this._retireBareField('federation', 'federation', value => value.stop(), timeout))
    await settleWriter(() => this._drainLifecycleAndSeededDrives(timeout))
    await settleWriter(() => this._retireBareField('seeder', 'seeder', value => value.stop(), timeout))
    if (this.appRegistry && this.store) {
      await settleWriter(async () => {
        await this._awaitOwnerOperation(
          this.appRegistry,
          'appRegistry.flush',
          () => this.appRegistry.flush({ throwOnError: true }),
          timeout
        )
      })
    }
    if (this.storageAdmission) this.storageAdmission.closeMutations('storage-startup-rollback')
    if (this.storageAdmission) {
      await this.storageAdmission.drainMutations({
        timeoutMs: this._remainingOwnerBudget(timeout)
      })
    }
    await settleWriter(() => this._destroyDiscoveryHandles(timeout))
    if (writerQuiesceError) {
      if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
      const failure = new Error('storage writer quiescence did not settle')
      failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
      failure.cause = writerQuiesceError
      throw failure
    }
    if (this.relay) {
      try {
        await this._retireBareField('relay', 'relay', value => value.stop(), timeout)
      } catch (relayErr) {
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
        const failure = new Error('relay teardown did not settle')
        failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
        failure.cause = relayErr
        throw failure
      }
    }
    if (this.swarm) {
      try {
        await this._retireBareField('swarm', 'swarm', value => value.destroy(), timeout)
      } catch (swarmErr) {
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
        const failure = new Error('swarm teardown did not settle')
        failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
        failure.cause = swarmErr
        throw failure
      }
    }
    if (this.swarmFirewall) { try { this.swarmFirewall.destroy() } catch (_) {} this.swarmFirewall = null }
    if (this.store) {
      try {
        await this._retireBareField('store', 'corestore', value => value.close(), timeout)
      } catch (storeErr) {
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
        const failure = new Error('corestore teardown did not settle')
        failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
        failure.cause = storeErr
        throw failure
      }
    }
    if (this.appRegistry) {
      try { this.appRegistry.detachStore() } catch (_) {}
      await this._retireBareRuntimeOwner(
        this.appRegistry,
        'appRegistry',
        async () => {},
        timeout,
        { retainRecord: true }
      )
    }
    await this._completeBareRuntimeShutdown(timeout)
    this.running = false
    this.startedAt = null
    this._startupRollbackPending = false
  }

  async _destroyProtocolHandlers (timeout) {
    let firstError = null
    for (const field of ['_serviceProtocol', '_seedProtocol', '_circuitRelay', '_proofOfRelay']) {
      const protocol = this[field]
      if (!protocol) continue
      try {
        await this._retireBareRuntimeOwner(
          protocol,
          field,
          typeof protocol.destroy === 'function' ? () => protocol.destroy() : async () => {},
          timeout
        )
        if (this[field] === protocol) this[field] = null
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  _ownerOperation (owner, label, run) {
    if (!(this._ownerOperations instanceof WeakMap)) this._ownerOperations = new WeakMap()
    const existing = this._ownerOperations.get(owner)
    if (existing) {
      if (existing.label === label) return existing.operation
      return existing.operation.catch(() => {}).then(() => this._ownerOperation(owner, label, run))
    }
    const operation = Promise.resolve().then(run)
    const entry = { label, operation }
    this._ownerOperations.set(owner, entry)
    operation.then(
      () => { if (this._ownerOperations.get(owner) === entry) this._ownerOperations.delete(owner) },
      () => { if (this._ownerOperations.get(owner) === entry) this._ownerOperations.delete(owner) }
    )
    return operation
  }

  _awaitOwnerOperation (owner, label, run, timeout) {
    // Arm the timeout when the owner-serialized operation actually STARTS,
    // not when it is queued behind an in-flight operation on the same owner,
    // and floor the budget so event-loop stalls between queueing and
    // execution cannot consume it before run() begins.
    return this._ownerOperation(owner, label, () => withTimeout(
      Promise.resolve().then(run),
      Math.max(MIN_OWNER_OPERATION_BUDGET_MS, this._remainingOwnerBudget(timeout)),
      label
    ))
  }

  _remainingOwnerBudget (timeout) {
    let budget = timeout || 30_000
    if (this._ownerDeadline) budget = Math.max(1, Math.min(budget, this._ownerDeadline - Date.now()))
    return budget
  }

  _adoptBareRuntimeOwner (owner, label) {
    if (!owner || (typeof owner !== 'object' && typeof owner !== 'function')) return null
    if (!(this._bareRuntimeOwners instanceof Map)) this._bareRuntimeOwners = new Map()
    let record = this._bareRuntimeOwners.get(owner)
    if (!record) {
      record = {
        owner,
        label,
        generation: null,
        state: 'LIVE',
        terminalSettled: false,
        terminalRaw: null
      }
      this._bareRuntimeOwners.set(owner, record)
    } else if (label && !record.label) {
      record.label = label
    }
    if (this._shutdownFence && this._shutdownFence.state !== 'COMPLETE') {
      this._fenceBareRuntimeOwner(record)
    }
    return record
  }

  _fenceBareRuntimeOwner (record) {
    if (!record || record.state !== 'LIVE') return record
    let state = sharedOperationFlights.getStats(record.owner).owner
    if (!state) {
      sharedOperationFlights.activateOwner(record.owner)
      state = sharedOperationFlights.getStats(record.owner).owner
    }
    record.generation = state.accepting
      ? sharedOperationFlights.invalidateOwner(record.owner, { retire: true })
      : state.generation
    record.state = 'FENCED'
    return record
  }

  _inventoryBareRuntimeOwners () {
    for (const [field, label] of [
      ['httpServer', 'httpServer'],
      ['_serviceProtocol', 'serviceProtocol'],
      ['_seedProtocol', 'seedProtocol'],
      ['_circuitRelay', 'circuitRelay'],
      ['_proofOfRelay', 'proofOfRelay'],
      ['serviceRegistry', 'serviceRegistry'],
      ['appCatalogController', 'appCatalogController'],
      ['federation', 'federation'],
      ['appLifecycle', 'appLifecycle'],
      ['seeder', 'seeder'],
      ['appRegistry', 'appRegistry'],
      ['relay', 'relay'],
      ['swarm', 'swarm'],
      ['store', 'corestore']
    ]) {
      this._adoptBareRuntimeOwner(this[field], label)
    }

    if (this.serviceRegistry?.services instanceof Map) {
      for (const [name, entry] of this.serviceRegistry.services) {
        this._adoptBareRuntimeOwner(entry?.provider, `service:${name}`)
      }
    }
    for (const [label, handle] of [
      ['relayDiscovery', this._discovery],
      ['foundationDiscovery', this._foundationDiscovery],
      ['regionDiscovery', this._regionDiscovery]
    ]) {
      this._adoptBareRuntimeOwner(handle, label)
    }
    if (this._epochDiscoveryTopics instanceof Map) {
      for (const [key, handle] of this._epochDiscoveryTopics) {
        this._adoptBareRuntimeOwner(handle, `epochDiscovery:${key}`)
      }
    }
    if (this._retiringEpochDiscoveryHandles instanceof Set) {
      for (const entry of this._retiringEpochDiscoveryHandles) {
        this._adoptBareRuntimeOwner(entry?.handle, 'retiringEpochDiscovery')
      }
    }
  }

  _installBareShutdownFence (reason) {
    let fence = this._shutdownFence
    if (fence?.state === 'COMPLETE') return fence
    if (!fence) {
      this._shutdownGeneration = Number.isSafeInteger(this._shutdownGeneration) && this._shutdownGeneration >= 0
        ? this._shutdownGeneration + 1
        : 1
      fence = {
        generation: this._shutdownGeneration,
        reason,
        state: 'FENCED',
        installedAt: Date.now(),
        firstError: null,
        serviceProtocolFenceOwner: null,
        serviceRegistryFenceOwner: null,
        appLifecycleFenceOwner: null,
        appCatalogControllerFenceOwner: null,
        settledDriveEntries: new WeakSet(),
        settledDriveKeys: new Set()
      }
      // Publish the process-wide fence before any externally callable hook.
      this._shutdownFence = fence
    }
    this._storageIngressReady = false
    this._stopRequested = true
    this._legacyCatalogAcceptedPeers?.clear()

    // Inventory and invalidate every already-published Bare owner before a
    // hook can synchronously re-enter and attempt a raw shared flight.
    this._inventoryBareRuntimeOwners()
    for (const record of this._bareRuntimeOwners.values()) this._fenceBareRuntimeOwner(record)

    let firstError = null
    try {
      if (this._scope && typeof this._scope.abort === 'function') this._scope.abort()
    } catch (err) {
      firstError = err
    }
    const fenceOwner = (slot, owner) => {
      if (!owner || fence[slot] === owner) return
      try {
        if (typeof owner.beginShutdown === 'function') owner.beginShutdown()
        fence[slot] = owner
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    fenceOwner('serviceProtocolFenceOwner', this._serviceProtocol)
    fenceOwner('serviceRegistryFenceOwner', this.serviceRegistry)
    fenceOwner('appLifecycleFenceOwner', this.appLifecycle)
    fenceOwner('appCatalogControllerFenceOwner', this.appCatalogController)
    // Only the current attempt's unresolved hook error is retained. A later
    // stop/rollback wave retries the same hook on the same owner/generation.
    fence.firstError = firstError
    return fence
  }

  _assertBareWorkAccepted (operation) {
    if (this._shutdownFence) throw shuttingDownError(operation)
  }

  _adoptBareStartupOwner (owner, label) {
    const record = this._adoptBareRuntimeOwner(owner, label)
    this._assertBareWorkAccepted('start')
    return record
  }

  _resetBareRuntimeCycle () {
    for (const record of this._bareRuntimeOwners.values()) {
      if (record.owner !== this && record.state !== 'CLOSED') {
        const err = new Error(`Bare runtime owner ${record.label} did not settle before restart`)
        err.code = 'BARE_OWNER_RETIREMENT_PENDING'
        throw err
      }
    }
    this._bareRuntimeOwners.clear()
    this._shutdownFence = null
    const record = this._adoptBareRuntimeOwner(this, 'bareRelay')
    record.generation = sharedOperationFlights.activateOwner(this)
  }

  async _drainBareRuntimeOwner (record, timeout) {
    if (!record || record.state === 'CLOSED') return
    await sharedOperationFlights.drainOwner(record.owner, {
      timeoutMs: Math.max(1, Math.min(120_000, this._remainingOwnerBudget(timeout)))
    })
  }

  async _retireBareRuntimeOwner (owner, label, terminal, timeout, opts = {}) {
    const record = this._adoptBareRuntimeOwner(owner, label)
    if (!record || record.state === 'CLOSED') return
    this._fenceBareRuntimeOwner(record)

    // First prefer a true drain. If a raw library flight settles only when its
    // exact owner closes, continue into that terminal-close subphase and prove
    // the drain again afterwards.
    let preDrainError = null
    try { await this._drainBareRuntimeOwner(record, timeout) } catch (err) { preDrainError = err }

    if (!record.terminalSettled) {
      try {
        const terminalTimeout = Number.isSafeInteger(timeout) && timeout > 0
          ? Math.max(MIN_OWNER_OPERATION_BUDGET_MS, Math.min(timeout, 60_000))
          : MIN_OWNER_OPERATION_BUDGET_MS
        if (!record.terminalRaw) {
          const raw = Promise.resolve().then(terminal)
          record.terminalRaw = raw
          raw.then(
            () => {
              if (record.terminalRaw !== raw) return
              record.terminalSettled = true
            },
            () => {
              // A true terminal rejection is settled and may be explicitly
              // retried. A waiter timeout never clears terminalRaw, so it can
              // neither lose nor duplicate an unresolved close call.
              if (record.terminalRaw === raw) record.terminalRaw = null
            }
          )
        }
        await withTimeout(record.terminalRaw, terminalTimeout, `${label}.terminalClose`)
        record.terminalSettled = true
      } catch (err) {
        if (preDrainError && !err.preDrainCause) err.preDrainCause = preDrainError
        throw err
      }
    }

    // terminal() proved this exact object cannot perform more work. Releasing
    // an orphan keyed by that same object is now safe; late raw settlement is
    // reduced to the registry's non-mutating sink.
    sharedOperationFlights.closeEntity(owner, `${label} terminal close settled`)
    await this._drainBareRuntimeOwner(record, timeout)
    record.state = 'CLOSED'
    if (owner !== this && opts.retainRecord !== true) this._bareRuntimeOwners.delete(owner)
  }

  async _drainBareServiceRequests (protocol, registry, timeout, phase) {
    let firstError = null
    for (const [owner, label] of [
      [protocol, `serviceProtocol.requests.${phase}`],
      [registry, `serviceRegistry.requests.${phase}`]
    ]) {
      if (!owner || typeof owner.drainRequests !== 'function') continue
      try {
        await withTimeout(
          owner.drainRequests(),
          this._remainingOwnerBudget(timeout),
          label
        )
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  async _stopBareServiceIngress (timeout) {
    const protocol = this._serviceProtocol
    if (!protocol) return
    const registry = this.serviceRegistry
    let preDrainError = null
    try {
      await this._drainBareServiceRequests(protocol, registry, timeout, 'preCloseDrain')
    } catch (err) {
      preDrainError = err
    }

    let terminalError = null
    try {
      await this._retireBareRuntimeOwner(
        protocol,
        'serviceProtocol',
        typeof protocol.destroy === 'function' ? () => protocol.destroy() : async () => {},
        timeout
      )
      if (this._serviceProtocol === protocol) this._serviceProtocol = null
    } catch (err) {
      terminalError = err
    }

    let postDrainError = null
    try {
      await this._drainBareServiceRequests(protocol, registry, timeout, 'postCloseDrain')
    } catch (err) {
      postDrainError = err
    }
    if (terminalError || postDrainError) {
      const error = terminalError || postDrainError
      if (preDrainError && !error.preDrainCause) error.preDrainCause = preDrainError
      throw error
    }
  }

  async _stopBareServices (timeout) {
    const registry = this.serviceRegistry
    if (!registry) return
    const providerRecords = []
    const seen = new Set()
    if (registry.services instanceof Map) {
      for (const [name, entry] of registry.services) {
        const record = this._adoptBareRuntimeOwner(entry?.provider, `service:${name}`)
        if (record && !seen.has(record.owner)) {
          seen.add(record.owner)
          providerRecords.push(record)
        }
      }
    }
    for (const record of this._bareRuntimeOwners.values()) {
      if (!record.label?.startsWith('service:') || seen.has(record.owner)) continue
      seen.add(record.owner)
      providerRecords.push(record)
    }

    let preDrainError = null
    if (typeof registry.drainRequests === 'function') {
      try {
        await withTimeout(
          registry.drainRequests(),
          this._remainingOwnerBudget(timeout),
          'serviceRegistry.requests.drain'
        )
      } catch (err) {
        preDrainError = err
      }
    }
    for (const record of providerRecords) {
      try { await this._drainBareRuntimeOwner(record, timeout) } catch (err) {
        if (!preDrainError) preDrainError = err
      }
    }

    let stopError = null
    try {
      await this._awaitOwnerOperation(
        registry,
        'serviceRegistry.stopAll',
        () => registry.stopAll({ throwOnError: true }),
        timeout
      )
    } catch (err) {
      stopError = err
    }

    const retainedProviders = new Set()
    if (registry.services instanceof Map) {
      for (const entry of registry.services.values()) retainedProviders.add(entry?.provider)
    }
    let postDrainError = null
    for (const record of providerRecords) {
      if (retainedProviders.has(record.owner)) continue
      record.terminalSettled = true
      sharedOperationFlights.closeEntity(record.owner, `${record.label} terminal close settled`)
      try {
        await this._drainBareRuntimeOwner(record, timeout)
        record.state = 'CLOSED'
        this._bareRuntimeOwners.delete(record.owner)
      } catch (err) {
        if (!postDrainError) postDrainError = err
      }
    }
    if (typeof registry.drainRequests === 'function') {
      try {
        await withTimeout(
          registry.drainRequests(),
          this._remainingOwnerBudget(timeout),
          'serviceRegistry.requests.postCloseDrain'
        )
      } catch (err) {
        if (!postDrainError) postDrainError = err
      }
    }

    if (stopError || postDrainError) {
      const error = stopError || postDrainError
      if (preDrainError && !error.preDrainCause) error.preDrainCause = preDrainError
      throw error
    }

    await this._retireBareRuntimeOwner(registry, 'serviceRegistry', async () => {}, timeout)
    if (this.serviceRegistry === registry) this.serviceRegistry = null
  }

  async _retireBareField (field, label, terminal, timeout) {
    const owner = this[field]
    if (!owner) return
    await this._retireBareRuntimeOwner(owner, label, () => terminal(owner), timeout)
    if (this[field] === owner) this[field] = null
  }

  async _completeBareRuntimeShutdown (timeout) {
    for (const record of [...this._bareRuntimeOwners.values()]) {
      if (record.owner === this || record.state === 'CLOSED') continue
      if (!record.terminalSettled) {
        const err = new Error(`Bare runtime owner ${record.label} has not completed terminal close`)
        err.code = 'BARE_OWNER_RETIREMENT_PENDING'
        throw err
      }
      sharedOperationFlights.closeEntity(record.owner, `${record.label} terminal close settled`)
      await this._drainBareRuntimeOwner(record, timeout)
      record.state = 'CLOSED'
      this._bareRuntimeOwners.delete(record.owner)
    }
    await this._retireBareRuntimeOwner(this, 'bareRelay', async () => {}, timeout)
    if (this._shutdownFence) this._shutdownFence.state = 'COMPLETE'
  }

  async _drainLifecycleAndSeededDrives (timeout) {
    const fence = this._installBareShutdownFence('lifecycle-drain')
    const scope = this._scope
    if (scope) {
      await withTimeout(scope.drain(), this._remainingOwnerBudget(timeout), 'lifecycleScope.drain')
      if (this._scope === scope) this._scope = null
    }
    if (!this.appLifecycle) return

    const registry = this.appRegistry
    if (!registry || typeof registry.page !== 'function' ||
        typeof registry.releasePopulationConsumer !== 'function') {
      const err = new Error('Bare seeded-drive retirement requires bounded registry paging')
      err.code = 'APP_REGISTRY_BOUNDED_PAGE_REQUIRED'
      throw err
    }

    let lastError = null
    let reachedStableWave = false
    try {
      for (let wave = 0; wave < BARE_RETIREMENT_MAX_WAVES; wave++) {
        let waveError = null
        let attempted = 0
        if (typeof this.appLifecycle.drainRetiringDrives === 'function') {
          try {
            await withTimeout(
              this.appLifecycle.drainRetiringDrives(),
              this._remainingOwnerBudget(timeout),
              'retiringDrives.drain'
            )
          } catch (err) {
            waveError = err
          }
        }

        let pageCalls = 0
        let page
        do {
          page = registry.page(
            BARE_RETIREMENT_POPULATION_CONSUMER,
            BARE_RETIREMENT_PAGE_BUDGET
          )
          pageCalls++
          if (!page || !Array.isArray(page.entries) ||
              page.entries.length > BARE_RETIREMENT_PAGE_BUDGET ||
              typeof page.complete !== 'boolean' ||
              (!page.complete && (!Number.isSafeInteger(page.examined) || page.examined < 1))) {
            const err = new Error('Bare seeded-drive retirement received an invalid registry page')
            err.code = 'APP_REGISTRY_BOUNDED_PAGE_INVALID'
            throw err
          }
          if (pageCalls > BARE_RETIREMENT_MAX_PAGE_CALLS) {
            const err = new Error('Bare seeded-drive retirement population bound was exceeded')
            err.code = 'APP_REGISTRY_BOUNDED_PAGE_EXHAUSTED'
            throw err
          }
          for (const item of page.entries) {
            const appKey = item?.key
            const entry = item?.value
            if (typeof appKey !== 'string') {
              const err = new Error('Bare seeded-drive retirement received an invalid registry key')
              err.code = 'APP_REGISTRY_BOUNDED_PAGE_INVALID'
              throw err
            }
            const settled = entry && (typeof entry === 'object' || typeof entry === 'function')
              ? fence.settledDriveEntries.has(entry)
              : fence.settledDriveKeys.has(appKey)
            if (settled) continue
            attempted++
            try {
              await withTimeout(
                this.appLifecycle.unseedApp(appKey, { forget: false }),
                this._remainingOwnerBudget(timeout),
                `unseedApp(${appKey.slice(0, 8)})`
              )
              if (entry && (typeof entry === 'object' || typeof entry === 'function')) {
                fence.settledDriveEntries.add(entry)
              } else {
                fence.settledDriveKeys.add(appKey)
              }
            } catch (err) {
              if (!waveError) waveError = err
            }
          }
        } while (!page.complete)

        lastError = waveError
        if (!waveError && attempted === 0) {
          reachedStableWave = true
          break
        }
      }

      if (lastError) throw lastError
      if (fence.firstError) throw fence.firstError
      if (typeof this.appLifecycle.drainRetiringDrives === 'function') {
        await withTimeout(
          this.appLifecycle.drainRetiringDrives(),
          this._remainingOwnerBudget(timeout),
          'retiringDrives.finalDrain'
        )
      }
      if (!reachedStableWave) {
        const err = new Error('Bare seeded-drive retirement did not reach a stable empty wave')
        err.code = 'BARE_OWNER_RETIREMENT_PENDING'
        throw err
      }
    } finally {
      registry.releasePopulationConsumer(BARE_RETIREMENT_POPULATION_CONSUMER)
    }

    await this._retireBareRuntimeOwner(
      this.appLifecycle,
      'appLifecycle',
      async () => {},
      timeout,
      { retainRecord: true }
    )
  }

  stop () {
    if (this._stopping) return this._stopping
    const operation = this._stop()
    const stopping = operation.finally(() => {
      if (this._stopping === stopping) this._stopping = null
      this._ownerDeadline = null
    })
    this._stopping = stopping
    return stopping
  }

  async _stop () {
    if (!this.running && !this._starting && !this._startupRollbackPending) return
    this._installBareShutdownFence('normal-stop')
    this._ownerDeadline = Date.now() + (this.config.shutdownTimeoutMs || 30_000)
    log.info('BareRelay stopping…')

    if (this._starting && this.storageAdmission) this.storageAdmission.closeMutations()
    if (this._starting && this._startCompletion) {
      const scopeDuringStart = this._scope
      if (scopeDuringStart) scopeDuringStart.abort()
      try {
        await withTimeout(
          this._startCompletion,
          this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000),
          'bare relay start completion'
        )
      } catch (cause) {
        if (cause?.code !== 'OPERATION_TIMEOUT') {
          if (this._startupRollbackPending) throw cause
          return
        }
        const failure = new Error('bare relay startup settlement is still pending')
        failure.code = 'STORAGE_START_TEARDOWN_PENDING'
        failure.cause = cause
        throw failure
      }
      if (scopeDuringStart && this._scope === scopeDuringStart) {
        try {
          await withTimeout(
            scopeDuringStart.drain(),
            this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000),
            'startup lifecycleScope.drain'
          )
          if (this._scope === scopeDuringStart) this._scope = null
        } catch (cause) {
          const failure = new Error('bare relay startup lifecycle teardown is still pending')
          failure.code = 'STORAGE_START_TEARDOWN_PENDING'
          failure.cause = cause
          throw failure
        }
      }
      if (!this.running) {
        return
      }
    }

    // Stop ingress and every append-capable provider while their final flush
    // can still use the authority. A failure seals admission and deliberately
    // leaves Corestore owned for a later supervisor retry.
    let writerQuiesceError = null
    const settleWriter = async (run) => {
      try { await run() } catch (err) { if (!writerQuiesceError) writerQuiesceError = err }
    }
    const timeout = this.config.shutdownTimeoutMs || 30_000
    if (this._epochDiscoveryTimer) { clearInterval(this._epochDiscoveryTimer); this._epochDiscoveryTimer = null }
    await settleWriter(() => this._retireBareField('httpServer', 'httpServer', server => server.stop(), timeout))
    await settleWriter(() => this._retireBareField(
      'appCatalogController',
      'appCatalogController',
      value => value.stop(),
      timeout
    ))
    this.appCatalogStore = null
    this._appCatalogStageFactory = null
    await settleWriter(() => this._stopBareServiceIngress(timeout))
    await settleWriter(() => this._destroyProtocolHandlers(timeout))
    await settleWriter(() => this._stopBareServices(timeout))
    await settleWriter(() => this._retireBareField('federation', 'federation', value => value.stop(), timeout))
    await settleWriter(() => this._drainLifecycleAndSeededDrives(timeout))
    await settleWriter(() => this._retireBareField('seeder', 'seeder', value => value.stop(), timeout))
    if (this.appRegistry) {
      await settleWriter(() => this._awaitOwnerOperation(
        this.appRegistry,
        'appRegistry.flush',
        () => this.appRegistry.flush({ throwOnError: true }),
        timeout
      ))
    }
    await settleWriter(() => this._destroyDiscoveryHandles(timeout))
    if (writerQuiesceError) {
      if (this.storageAdmission) {
        this.storageAdmission.closeMutations('storage-writer-quiesce-failed')
        this.storageAdmission.failClosed('storage-writer-quiesce-failed')
      }
      const failure = new Error('storage writer quiescence did not settle')
      failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
      failure.cause = writerQuiesceError
      throw failure
    }
    if (this.storageAdmission) this.storageAdmission.closeMutations()
    if (this.storageAdmission) {
      await this.storageAdmission.drainMutations({
        timeoutMs: this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000)
      })
    }

    if (this.relay) {
      await this._retireBareField('relay', 'relay', value => value.stop(), timeout)
    }
    if (this.swarm) {
      await this._retireBareField('swarm', 'swarm', value => value.destroy(), timeout)
    }
    if (this.swarmFirewall) { try { this.swarmFirewall.destroy() } catch (_) {} this.swarmFirewall = null }
    if (this.store) {
      await this._retireBareField('store', 'corestore', value => value.close(), timeout)
    }
    if (this.appRegistry) {
      try { this.appRegistry.detachStore() } catch (_) {}
      await this._retireBareRuntimeOwner(
        this.appRegistry,
        'appRegistry',
        async () => {},
        timeout,
        { retainRecord: true }
      )
    }

    await this._completeBareRuntimeShutdown(timeout)
    this.running = false
    this._startupRollbackPending = false
    this._ownerDeadline = null
    this.emit('stopped')
    log.info('BareRelay stopped.')
  }

  // ─── Keypair persistence ─────────────────────────────────────────

  async _deriveKeypair () {
    const keyPath = join(this.config.storage, 'identity.key')
    try {
      const hex = await readFile(keyPath, 'utf-8')
      const seed = b4a.from(hex.trim(), 'hex')
      const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
      const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
      sodium.crypto_sign_seed_keypair(pk, sk, seed)
      return { publicKey: pk, secretKey: sk }
    } catch {
      // Generate a new keypair and persist the seed
      const seed = b4a.alloc(sodium.crypto_sign_SEEDBYTES)
      sodium.randombytes_buf(seed)
      const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
      const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
      sodium.crypto_sign_seed_keypair(pk, sk, seed)
      await mkdir(this.config.storage, { recursive: true }).catch(() => {})
      const tmpPath = identityTempPath(keyPath)
      try {
        await writeFile(tmpPath, b4a.toString(seed, 'hex'), { mode: 0o600 })
        await chmod(tmpPath, 0o600)
        await rename(tmpPath, keyPath)
      } catch (err) {
        try { await unlink(tmpPath) } catch (_) {}
        throw err
      }
      return { publicKey: pk, secretKey: sk }
    }
  }

  // ─── Connection handling ─────────────────────────────────────────

  _onConnection (conn, info) {
    if (this._shutdownFence || !this._storageIngressReady) {
      // Guard the destroy: the remote can reset while it lands, and a Noise
      // stream erroring with no listener takes down the whole process.
      conn.on('error', () => {})
      try { conn.destroy() } catch (_) {}
      return
    }
    const remotePublicKey = conn.remotePublicKey || info?.publicKey || null
    const remoteHex = remotePublicKey ? b4a.toString(remotePublicKey, 'hex') : null
    log.info('  + peer:', remoteHex ? remoteHex.slice(0, 16) : 'anon')
    this.connections.set(conn, { lastActivity: Date.now() })

    // Each protocol owns an independent channel. A fault in one optional
    // attachment must not suppress seed, relay, proof, or legacy ingress.
    const attach = (name, fn) => {
      try { fn() } catch (err) { log.warn(`  ${name} protocol attach error:`, err.message) }
    }
    if (this.appCatalogController && remotePublicKey) {
      attach('app-catalog', () => this.appCatalogController.attach(conn, remotePublicKey))
    }
    if (this._seedProtocol) attach('seed', () => this._seedProtocol.attach(conn, info))
    if (this._circuitRelay) attach('circuit-relay', () => this._circuitRelay.attach(conn, info))
    if (this._proofOfRelay) attach('proof-of-relay', () => this._proofOfRelay.attach(conn, info))
    if (this._serviceProtocol && remoteHex) {
      attach('service', () => this._serviceProtocol.attach(conn, remoteHex))
    }

    // Always replicate the corestore — this is how we serve seeded content
    this.store.replicate(conn)

    conn.on('error', (err) => {
      // Classify: normal P2P drops (ECONNRESET / ETIMEDOUT / duplicate conn
      // races) are noise on the public DHT and should not alarm. Emit a
      // low-severity event for observability without logging every one.
      const code = err && (err.code || err.message || '')
      const benign = /ECONNRESET|ETIMEDOUT|EPIPE|Duplicate connection|channel destroyed/i.test(code)
      if (benign) {
        this.emit('connection-drop', { reason: err.code || err.message, info })
      } else {
        log.warn('  connection error:', code)
        this.emit('connection-error', { error: err, info })
      }
    })

    conn.on('close', () => {
      this.connections.delete(conn)
    })

    this.emit('connection', { info, remotePubKey: remoteHex })
  }

  // ─── Seed/unseed handlers ────────────────────────────────────────

  /**
   * Verify a delegation cert chain on a seed request. Mirrors the Node
   * RelayNode's `_checkDelegation` so the two runtimes give identical
   * answers for identical input.
   *
   * @returns {{ok: true, primaryPubkey: string} | {ok: false, reason: string}}
   */
  /**
   * Accept a signed revocation. Same semantics as RelayNode.submitRevocation.
   */
  submitRevocation (rev, opts = {}) {
    const result = verifyRevocation(rev)
    if (!result.valid) return { ok: false, reason: result.reason || 'invalid revocation' }
    const expiresAt = typeof opts.certExpiresAt === 'number' && opts.certExpiresAt > 0
      ? opts.certExpiresAt
      : Date.now() + 30 * 24 * 60 * 60 * 1000
    this._revokedCertSignatures.set(rev.revokedCertSignature, {
      revokedAt: rev.revokedAt,
      expiresAt,
      reason: rev.reason || '',
      primaryPubkey: rev.primaryPubkey
    })
    this.emit('delegation-revoked', {
      revokedCertSignature: rev.revokedCertSignature,
      primaryPubkey: rev.primaryPubkey,
      reason: rev.reason || ''
    })
    return { ok: true, revokedCertSignature: rev.revokedCertSignature }
  }

  listRevocations () {
    const out = []
    for (const [sig, entry] of this._revokedCertSignatures) {
      out.push({ revokedCertSignature: sig, ...entry })
    }
    return out
  }

  _checkDelegation (msg) {
    const cert = msg.delegationCert
    const result = verifyDelegationCert(cert)
    if (!result.valid) return { ok: false, reason: result.reason || 'invalid cert' }

    // Revocation check — if the primary has invalidated this cert early,
    // reject regardless of other checks passing.
    if (cert.signature && this._revokedCertSignatures.has(cert.signature)) {
      return { ok: false, reason: 'revoked' }
    }

    // Whose signature is on the seed request?
    const reqPublisher = msg.publisherPubkey
      ? b4a.toString(msg.publisherPubkey, 'hex').toLowerCase()
      : null
    if (!reqPublisher) return { ok: false, reason: 'missing request publisher' }

    if (reqPublisher !== cert.devicePubkey.toLowerCase()) {
      return { ok: false, reason: 'cert.devicePubkey mismatch' }
    }

    // Verify the seed-request's own signature was produced by the device key
    // named in the cert. Without this check the cert is a stamp attached to a
    // request nobody can prove the device actually made.
    if (!msg.publisherSignature) return { ok: false, reason: 'missing request signature' }
    const sigBuf = typeof msg.publisherSignature === 'string'
      ? b4a.from(msg.publisherSignature, 'hex')
      : msg.publisherSignature
    if (!sigBuf || sigBuf.length !== 64) {
      return { ok: false, reason: 'malformed request signature' }
    }

    const devicePk = b4a.from(cert.devicePubkey, 'hex')
    // Reconstruct the same payload SeedProtocol signs: appKey || hash(discoveryKeys) || meta(28)
    const appKeyBuf = typeof msg.appKey === 'string' ? b4a.from(msg.appKey, 'hex') : msg.appKey
    if (!appKeyBuf || appKeyBuf.length !== 32) {
      return { ok: false, reason: 'malformed appKey' }
    }

    const dkHash = b4a.alloc(32)
    const dks = Array.isArray(msg.discoveryKeys) ? msg.discoveryKeys : []
    if (dks.length > 0) {
      const dkBufs = dks.map(dk => typeof dk === 'string' ? b4a.from(dk, 'hex') : dk)
      sodium.crypto_generichash(dkHash, b4a.concat(dkBufs))
    }
    const meta = b4a.alloc(28)
    const view = new DataView(meta.buffer, meta.byteOffset)
    view.setUint8(0, msg.replicationFactor || 0)
    view.setBigUint64(8, BigInt(msg.maxStorageBytes || 0))
    view.setBigUint64(16, BigInt(msg.ttlSeconds || 0))
    view.setUint32(24, msg.bountyRate || 0)

    const payload = b4a.concat([appKeyBuf, dkHash, meta])
    const ok = sodium.crypto_sign_verify_detached(sigBuf, payload, devicePk)
    if (!ok) return { ok: false, reason: 'request signature mismatch' }

    return { ok: true, primaryPubkey: result.primaryPubkey }
  }

  async _onSeedRequest (msg, channel = null, trackedMutation = false) {
    if (this._shutdownFence) {
      const err = shuttingDownError('seed request')
      if (channel && this._seedProtocol && msg?.appKey) {
        try { this._seedProtocol.denySeedRequest(channel, msg.appKey, 'shutting-down', err.message) } catch (_) {}
      }
      throw err
    }
    if (!trackedMutation && this.storageAdmission?.runMutation) {
      return this.storageAdmission.runMutation(() => this._onSeedRequest(msg, channel, true))
    }
    if (!this.config.enableSeeding || !this.seeder) return
    const appKeyHex = b4a.toString(msg.appKey, 'hex')

    // Wire-level deny so the publisher sees why instead of timing out —
    // same contract as the Node RelayNode handler.
    const deny = (reasonCode, detail) => {
      if (channel && this._seedProtocol) {
        this._seedProtocol.denySeedRequest(channel, msg.appKey, reasonCode, detail)
      }
    }

    const maxStorageBytes = positiveStorageBound(msg.maxStorageBytes)
    if (maxStorageBytes === null) {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'storage-bound-invalid' })
      deny('storage-bound-invalid', 'maxStorageBytes must be a positive safe integer')
      return
    }
    const discoveryHints = validateSeedDiscoveryHints(msg.appKey, msg.discoveryKeys || [])
    if (!discoveryHints.ok) {
      log.warn('  seed rejected (discovery hints):', appKeyHex.slice(0, 16), '-', discoveryHints.reason)
      this.emit('seed-rejected', { appKey: appKeyHex, reason: discoveryHints.reason })
      deny('unsupported-discovery-key-set', discoveryHints.reason)
      return
    }

    // Apply the same accept-mode gate as the Node RelayNode. Bare has no
    // operator TUI, so 'review' isn't actionable in this runtime — coerce
    // it to 'closed' (operator must explicitly opt into 'open' or
    // 'allowlist' to accept anything in Bare).
    let mode = resolveAcceptMode(this.config)
    if (mode === 'review') mode = 'closed'
    const decision = decideAcceptance(msg, mode, this.config.acceptAllowlist || [])
    if (decision === 'reject') {
      log.warn('  seed rejected (acceptMode=' + mode + '):', appKeyHex.slice(0, 16))
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'acceptMode:' + mode })
      deny('accept-mode:' + mode, mode === 'allowlist'
        ? 'publisher is not on this relay\'s accept allowlist'
        : 'relay is not accepting inbound seed requests')
      return
    }

    // Device-attestation path: if a delegation cert is attached, verify the
    // chain. On success we attribute the seed to the primary identity (not
    // the device that signed the request). On failure we reject and emit.
    let effectivePublisher = msg.publisherPubkey ? b4a.toString(msg.publisherPubkey, 'hex') : null
    if (msg.delegationCert) {
      const delegationCheck = this._checkDelegation(msg)
      if (!delegationCheck.ok) {
        log.warn('  seed rejected (delegation):', appKeyHex.slice(0, 16), '-', delegationCheck.reason)
        this.emit('delegation-rejected', {
          appKey: appKeyHex,
          publisher: effectivePublisher,
          reason: delegationCheck.reason
        })
        this.emit('seed-rejected', { appKey: appKeyHex, reason: 'delegation:' + delegationCheck.reason })
        deny('delegation:' + delegationCheck.reason, 'delegation certificate chain failed verification')
        return
      }
      effectivePublisher = delegationCheck.primaryPubkey
    }

    // Propagate revocability commitments + any atomic-custody linkage from
    // the signed seed request, matching the Node relay's _onSeedRequest. The
    // custody fields keep parity with the publish-channel path so a custody
    // seed accepted here records the same intent binding (see
    // extractCustodySeedOpts). The binary wire encoding doesn't yet carry
    // them, so they only arrive on an enriched msg today.
    try {
      await this.appLifecycle.seedApp(appKeyHex, {
        publisherPubkey: effectivePublisher,
        maxStorage: maxStorageBytes,
        revocable: msg.revocable !== false,
        unseedFreezeMs: msg.unseedFreezeMs || 0,
        durability: msg.durability || 0,
        blind: msg.blind === true,
        storageClass: msg.storageClass || null,
        availabilityClass: msg.availabilityClass || null,
        ...extractCustodySeedOpts(msg)
      })
    } catch (err) {
      log.warn('  seed error:', err.message)
      this.emit('seed-error', { appKey: appKeyHex, error: err })
      deny('storage-admission-blocked', err.message || 'durable storage admission failed')
      return
    }

    if (this._shutdownFence) {
      this._emitSafely('seed-rejected', { appKey: appKeyHex, reason: 'SHUTTING_DOWN' })
      deny('shutting-down', 'relay shutdown began before seed acknowledgement')
      return
    }

    if (!this.storageAdmission?.canAcknowledge?.(`drive:${appKeyHex}`)) {
      try { this.emit('seed-ack-error', { appKey: appKeyHex, error: new Error('storage commitment is not acknowledgeable') }) } catch (_) {}
      return
    }
    try {
      this._seedProtocol.acceptSeedRequest(
        msg.appKey,
        this.swarm.keyPair.publicKey,
        (this.config.regions && this.config.regions[0]) || 'unknown',
        this._informationalAvailableStorageBytes()
      )
    } catch (err) {
      try { this.emit('seed-ack-error', { appKey: appKeyHex, error: err }) } catch (_) {}
      return
    }
    log.info('  ✓ seeded:', appKeyHex.slice(0, 16))
    try { this.emit('seed-accepted', { appKey: appKeyHex, mode, publisherPubkey: effectivePublisher }) } catch (_) {}
  }

  _onUnseedRequest (msg) {
    if (this._shutdownFence) {
      const appKey = msg?.appKey ? b4a.toString(msg.appKey, 'hex') : null
      this._emitSafely('unseed-rejected', { appKey, reason: 'SHUTTING_DOWN' })
      return false
    }
    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    const publisherHex = b4a.toString(msg.publisherPubkey, 'hex')
    const signatureHex = b4a.toString(msg.signature, 'hex')
    const result = this.appLifecycle.verifyUnseedRequest(
      appKeyHex, publisherHex, signatureHex, msg.timestamp
    )
    if (!result.ok) {
      log.warn('  unseed rejected:', result.error)
      this.emit('unseed-rejected', { appKey: appKeyHex, reason: result.error })
      return
    }
    this.appLifecycle.unseedApp(appKeyHex).then(() => {
      log.info('  ✓ unseeded:', appKeyHex.slice(0, 16))
    }).catch((err) => {
      log.warn('  unseed error:', err.message)
    })
  }

  // Used by AppLifecycle for parent drive lookup (distributed-drive compat).
  // In Bare mode we don't bridge distributed-drive, so return null.
  get distributedDriveBridge () { return null }
}

// Re-export so pear-entry.js can do:
//   import { BareRelay } from './core/relay-node/bare-relay.js'
export default BareRelay
