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
import { openCorestore } from '../persistence/storage-root-restore.js'
import b4a from 'b4a'
import sodium from 'sodium-universal'
// Use Node-shaped names. Under Bare/Pear they get remapped via the
// package.json `imports` map to bare-events / bare-fs/promises / bare-path.
// Under Node they resolve to the built-ins. This lets the same source file
// import cleanly in both runtimes.
import { EventEmitter } from 'events'
import { readFile, writeFile, mkdir, chmod, rename, unlink } from 'fs/promises'
import { join } from 'path'

import { Seeder } from './seeder.js'
import { Relay } from './relay.js'
import { AppLifecycle } from './app-lifecycle.js'
import { LifecycleScope } from './lifecycle-scope.js'
import { SeedProtocol } from '../protocol/seed-request.js'
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

const DEFAULT_CONFIG = {
  storage: './storage',
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
  acceptAllowlist: []
}

export class BareRelay extends EventEmitter {
  constructor (opts = {}) {
    super()
    this._storagePathExplicit = Object.prototype.hasOwnProperty.call(opts, 'storage')
    this.config = { ...DEFAULT_CONFIG, ...opts }
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
    this.appLifecycle = null
    this._seedProtocol = null
    this._circuitRelay = null
    this._proofOfRelay = null
    this._serviceProtocol = null
    this.serviceRegistry = null
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
    this.storageAdmission = new StorageAdmissionAuthority(this.config, {
      getUsedBytes: () => this._storageUsedBytes(),
      getActualBytes: (key) => this._storageActualBytes(key),
      recoveryKinds: ['drives', 'cores'],
      physicalEnforcer: this.config.physicalEnforcer || null
    })
  }

  // Symmetry with RelayNode so Federation can call it.
  _joinEpochDiscoveryTopics () {
    if (!this.swarm) return
    this._epochDiscoveryTopics = syncEpochDiscoveryTopics(
      this._epochDiscoveryTopics,
      this.swarm,
      { server: true, client: false },
      null,
      DISCOVERY_EPOCH_MS,
      (handle) => this._queueEpochDiscoveryDestroy(handle)
    )
  }

  _queueEpochDiscoveryDestroy (handle) {
    if (!handle || typeof handle.destroy !== 'function') return
    const entry = { handle, promise: null }
    this._retiringEpochDiscoveryHandles.add(entry)
    const run = Promise.resolve().then(() => handle.destroy())
    entry.promise = run
    run.then(
      () => this._retiringEpochDiscoveryHandles.delete(entry),
      () => { entry.promise = null }
    )
  }

  async _destroyDiscoveryHandles (timeout) {
    const destroy = async (handle, label) => {
      if (!handle || typeof handle.destroy !== 'function') return
      await this._awaitOwnerOperation(handle, label, () => handle.destroy(), timeout)
    }
    for (const entry of [...this._retiringEpochDiscoveryHandles]) {
      if (entry.promise) {
        await this._awaitOwnerOperation(
          entry,
          'retiringEpochDiscovery.destroy',
          () => entry.promise,
          timeout
        )
      } else {
        await destroy(entry.handle, 'retiringEpochDiscovery.destroy')
      }
      this._retiringEpochDiscoveryHandles.delete(entry)
    }
    for (const [key, handle] of this._epochDiscoveryTopics) {
      await destroy(handle, `epochDiscovery(${key.slice(0, 8)}).destroy`)
      this._epochDiscoveryTopics.delete(key)
    }
    for (const [field, label] of [
      ['_foundationDiscovery', 'foundationDiscovery.destroy'],
      ['_regionDiscovery', 'regionDiscovery.destroy'],
      ['_discovery', 'relayDiscovery.destroy']
    ]) {
      if (!this[field]) continue
      await destroy(this[field], label)
      this[field] = null
    }
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

  _storageAdmission (additionalBytes = 0) {
    return this.storageAdmission.admission(additionalBytes, { refresh: true })
  }

  get publicKey () { return this.swarm ? this.swarm.keyPair.publicKey : null }
  get seededApps () { return this.appRegistry ? this.appRegistry.apps : new Map() }
  seedApp (appKey, opts) { return this.appLifecycle.seedApp(appKey, opts) }
  unseedApp (appKey, opts) { return this.appLifecycle.unseedApp(appKey, opts) }

  // The Node RelayNode sets this.keyPair; Bare only has this.swarm.keyPair.
  // Alias it so services that sign with the relay identity (e.g. storage-proof)
  // work identically on both runtimes.
  get keyPair () { return this.swarm ? this.swarm.keyPair : null }

  start () {
    if (this._startCompletion) return this._startCompletion
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
    this._stopRequested = false
    this._storageIngressReady = false
    this._scope = new LifecycleScope()

    try {
      log.info('BareRelay starting…')
      log.info('  storage:', this.config.storage)

      // Only the built-in relative default may be created automatically;
      // custom paths must pre-exist so a missing mount fails closed.
      if (!this._storagePathExplicit) await mkdir(this.config.storage, { recursive: true })
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

      // 1. Corestore — persistent hypercore storage.
      // openCorestore, not `new Corestore`: Corestore 7 sweeps every
      // unrecognised top-level entry of a pre-7 root into db/ *inside its
      // constructor*, which would strand app-registry.json and evicted.json
      // before load() below can migrate them. See storage-root-restore.js.
      this.store = openCorestore(this.config.storage)
      await this.store.ready()

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
      this.appRegistry.setStore(this.store)
      await this.appRegistry.load()

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

      // 4. Seeder — pulls and keeps hypercores replicating
      this.seeder = new Seeder(this.store, this.swarm, {
        maxStorageBytes: this.config.maxStorageBytes,
        storageAdmission: this.storageAdmission,
        storagePath: join(this.config.storage, 'seeded-cores.json')
      })
      await this.seeder.start()

      // 5. Relay for circuit traversal (optional)
      if (this.config.enableRelay) {
        this.relay = new Relay(this.swarm, {
          maxCircuits: 256,
          maxBandwidthMbps: 100
        })
      }

      // 6. Protocol handlers — these attach to every incoming connection.
      // SeedProtocol has signature (swarm, opts); event-driven API.
      this._seedProtocol = new SeedProtocol(this.swarm, { keyPair: this.swarm.keyPair })
      this._seedProtocol.on('seed-request', (msg, channel) => {
        this._onSeedRequest(msg, channel).catch((err) => this.emit('seed-error', { error: err }))
      })
      this._seedProtocol.on('unseed-request', (msg) => this._onUnseedRequest(msg))

      this._circuitRelay = this.relay
        ? new CircuitRelay(this.relay)
        : null
      this._proofOfRelay = new ProofOfRelay(this.swarm.keyPair)

      // 7. App lifecycle — seed/unseed/index operations
      this.appLifecycle = new AppLifecycle(this)
      // Core inventory sealed in Seeder.start(); seal the drive inventory before
      // any storage-producing service provider is constructed or started.
      const reseedEntries = await this.appLifecycle.loadRegistry()
      if (!this.storageAdmission.recoveryReady) {
        const err = new Error('storage recovery inventories did not seal before writable services')
        err.code = 'STORAGE_RECOVERY_INVENTORY_INCOMPLETE'
        throw err
      }
      this._storageIngressReady = true
      this.swarm.on('connection', (conn, info) => this._onConnection(conn, info))

      // 8. Services layer — Bare-safe subset.
      //
      // We dynamic-import each builtin from p2p-hiveservices so that:
      //   - operators who only install Core get a clean "no services" mode
      //   - Compute and AI builtins, which need Node-only deps (vm / dns), are
      //     simply not in the list below
      if (this.config.enableServices !== false) {
        this.serviceRegistry = new ServiceRegistry()
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
          try {
            const mod = await import(spec.module)
            const Ctor = mod[spec.className]
            if (!Ctor) {
              log.warn('  service skipped (missing export):', spec.name)
              continue
            }
            const provider = new Ctor(spec.opts || {})
            this.serviceRegistry.register(provider)
            registered++
          } catch (err) {
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
          registered = startup.started.length
          for (const failure of startup.failed) {
            log.warn('  service start failed:', failure.name, '-', failure.error)
          }
          // ServiceProtocol signature is (registry, opts)
          // Secure-by-default: anonymous swarm peers cannot reach
          // authenticated-user/relay-admin routes. Operators opt into an open
          // surface explicitly via config.serviceDefaultPeerRole.
          this._serviceProtocol = new ServiceProtocol(this.serviceRegistry, {
            defaultPeerRole: (this.config && this.config.serviceDefaultPeerRole) || 'anonymous'
          })
          log.info('  services:', registered, 'registered')
        }
      }

      // 9. Optional minimal HTTP server (bare-http1) — read-only endpoints
      if (this.config.enableHttp !== false) {
        this.httpServer = new BareHttpServer(this, {
          port: this.config.httpPort,
          host: this.config.httpHost || '0.0.0.0'
        })
        try {
          const { port } = await this.httpServer.start()
          log.info('  http: http://127.0.0.1:' + port + '/status')
        } catch (startErr) {
          const server = this.httpServer
          try {
            await this._awaitOwnerOperation(
              server,
              'httpServer.stop',
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
      try { await this.federation.load() } catch (err) { log.warn('  federation load failed:', err.message) }
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

      // 9. Replay any previously-seeded apps from the registry
      if (this.config.enableSeeding) {
        await this.appLifecycle.reseedDrives(reseedEntries)
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
        this._startupRollbackPending = rollbackErr.code === 'STORAGE_MUTATION_DRAIN_TIMEOUT' ||
          rollbackErr.code === 'STORAGE_WRITER_QUIESCE_FAILED'
      } finally {
        this._ownerDeadline = null
      }
      throw failure
    }
  }

  async _rollbackFailedStart () {
    this._storageIngressReady = false
    let writerQuiesceError = null
    if (this._epochDiscoveryTimer) { clearInterval(this._epochDiscoveryTimer); this._epochDiscoveryTimer = null }
    if (this.httpServer) {
      const server = this.httpServer
      try {
        await this._awaitOwnerOperation(
          server,
          'httpServer.stop',
          () => server.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.httpServer === server) this.httpServer = null
      } catch (stopErr) {
        writerQuiesceError = stopErr
      }
    }
    try {
      await this._destroyProtocolHandlers(this.config.shutdownTimeoutMs || 30_000)
    } catch (stopErr) {
      writerQuiesceError = stopErr
    }
    if (this.serviceRegistry) {
      const registry = this.serviceRegistry
      try {
        await this._awaitOwnerOperation(
          registry,
          'serviceRegistry.stopAll',
          () => registry.stopAll({ throwOnError: true }),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.serviceRegistry === registry) this.serviceRegistry = null
      } catch (stopErr) {
        writerQuiesceError = stopErr
      }
    }
    if (this.federation) {
      const federation = this.federation
      try {
        await this._awaitOwnerOperation(
          federation,
          'federation.stop',
          () => federation.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.federation === federation) this.federation = null
      } catch (stopErr) {
        if (!writerQuiesceError) writerQuiesceError = stopErr
      }
    }
    try {
      await this._drainLifecycleAndSeededDrives(this.config.shutdownTimeoutMs || 30_000)
    } catch (stopErr) {
      if (!writerQuiesceError) writerQuiesceError = stopErr
    }
    if (this.seeder) {
      const seeder = this.seeder
      try {
        await this._awaitOwnerOperation(
          seeder,
          'seeder.stop',
          () => seeder.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.seeder === seeder) this.seeder = null
      } catch (stopErr) {
        if (!writerQuiesceError) writerQuiesceError = stopErr
      }
    }
    if (this.appRegistry && this.store) {
      try {
        await this._awaitOwnerOperation(
          this.appRegistry,
          'appRegistry.flush',
          () => this.appRegistry.flush({ throwOnError: true }),
          this.config.shutdownTimeoutMs || 30_000
        )
      } catch (flushErr) {
        if (!writerQuiesceError) writerQuiesceError = flushErr
      }
    }
    if (this.storageAdmission) this.storageAdmission.closeMutations('storage-startup-rollback')
    if (this.storageAdmission) {
      await this.storageAdmission.drainMutations({
        timeoutMs: this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000)
      })
    }
    try {
      await this._destroyDiscoveryHandles(this.config.shutdownTimeoutMs || 30_000)
    } catch (discoveryErr) {
      if (!writerQuiesceError) writerQuiesceError = discoveryErr
    }
    if (writerQuiesceError) {
      if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
      const failure = new Error('storage writer quiescence did not settle')
      failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
      failure.cause = writerQuiesceError
      throw failure
    }
    if (this.relay) {
      const relay = this.relay
      try {
        await this._awaitOwnerOperation(
          relay,
          'relay.stop',
          () => relay.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.relay === relay) this.relay = null
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
        const swarm = this.swarm
        await this._awaitOwnerOperation(
          swarm,
          'swarm.destroy',
          () => swarm.destroy(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.swarm === swarm) this.swarm = null
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
      const store = this.store
      try {
        await this._awaitOwnerOperation(
          store,
          'store.close',
          () => store.close(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.store === store) this.store = null
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
    }
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
        if (typeof protocol.destroy === 'function') {
          await this._awaitOwnerOperation(
            protocol,
            `${field}.destroy`,
            () => protocol.destroy(),
            timeout
          )
        }
        if (this[field] === protocol) this[field] = null
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  _ownerOperation (owner, label, run) {
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
    const budget = this._remainingOwnerBudget(timeout)
    return withTimeout(this._ownerOperation(owner, label, run), budget, label)
  }

  _remainingOwnerBudget (timeout) {
    let budget = timeout || 30_000
    if (this._ownerDeadline) budget = Math.max(1, Math.min(budget, this._ownerDeadline - Date.now()))
    return budget
  }

  async _drainLifecycleAndSeededDrives (timeout) {
    const scope = this._scope
    if (scope) {
      await withTimeout(scope.drain(), this._remainingOwnerBudget(timeout), 'lifecycleScope.drain')
      if (this._scope === scope) this._scope = null
    }
    if (!this.appLifecycle || !this.appRegistry) return
    if (typeof this.appLifecycle.drainRetiringDrives === 'function') {
      await withTimeout(
        this.appLifecycle.drainRetiringDrives(),
        this._remainingOwnerBudget(timeout),
        'retiringDrives.drain'
      )
    }
    for (const appKey of [...this.appRegistry.apps.keys()]) {
      await withTimeout(
        this.appLifecycle.unseedApp(appKey, { forget: false }),
        this._remainingOwnerBudget(timeout),
        `unseedApp(${appKey.slice(0, 8)})`
      )
    }
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
    this._stopRequested = true
    this._storageIngressReady = false
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
    try {
      if (this._epochDiscoveryTimer) { clearInterval(this._epochDiscoveryTimer); this._epochDiscoveryTimer = null }
      if (this.httpServer) {
        const server = this.httpServer
        await this._awaitOwnerOperation(server, 'httpServer.stop', () => server.stop(), this.config.shutdownTimeoutMs || 30_000)
        if (this.httpServer === server) this.httpServer = null
      }
      await this._destroyProtocolHandlers(this.config.shutdownTimeoutMs || 30_000)
      if (this.serviceRegistry) {
        const registry = this.serviceRegistry
        await this._awaitOwnerOperation(
          registry,
          'serviceRegistry.stopAll',
          () => registry.stopAll({ throwOnError: true }),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.serviceRegistry === registry) this.serviceRegistry = null
      }
      if (this.federation) {
        const federation = this.federation
        await this._awaitOwnerOperation(
          federation,
          'federation.stop',
          () => federation.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.federation === federation) this.federation = null
      }
      await this._drainLifecycleAndSeededDrives(this.config.shutdownTimeoutMs || 30_000)
      if (this.seeder) {
        const seeder = this.seeder
        await this._awaitOwnerOperation(
          seeder,
          'seeder.stop',
          () => seeder.stop(),
          this.config.shutdownTimeoutMs || 30_000
        )
        if (this.seeder === seeder) this.seeder = null
      }
      if (this.appRegistry) {
        await this._awaitOwnerOperation(
          this.appRegistry,
          'appRegistry.flush',
          () => this.appRegistry.flush({ throwOnError: true }),
          this.config.shutdownTimeoutMs || 30_000
        )
      }
      await this._destroyDiscoveryHandles(this.config.shutdownTimeoutMs || 30_000)
    } catch (err) {
      if (this.storageAdmission) {
        this.storageAdmission.closeMutations('storage-writer-quiesce-failed')
        this.storageAdmission.failClosed('storage-writer-quiesce-failed')
      }
      const failure = new Error('storage writer quiescence did not settle')
      failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
      failure.cause = err
      throw failure
    }
    if (this.storageAdmission) this.storageAdmission.closeMutations()
    if (this.storageAdmission) {
      await this.storageAdmission.drainMutations({
        timeoutMs: this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000)
      })
    }

    if (this.relay) {
      const relay = this.relay
      await this._awaitOwnerOperation(relay, 'relay.stop', () => relay.stop(), this.config.shutdownTimeoutMs || 30_000)
      if (this.relay === relay) this.relay = null
    }
    if (this.swarm) {
      const swarm = this.swarm
      await this._awaitOwnerOperation(swarm, 'swarm.destroy', () => swarm.destroy(), this.config.shutdownTimeoutMs || 30_000)
      if (this.swarm === swarm) this.swarm = null
    }
    if (this.swarmFirewall) { try { this.swarmFirewall.destroy() } catch (_) {} this.swarmFirewall = null }
    if (this.store) {
      const store = this.store
      await this._awaitOwnerOperation(store, 'store.close', () => store.close(), this.config.shutdownTimeoutMs || 30_000)
      if (this.store === store) this.store = null
    }

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
    if (!this._storageIngressReady) {
      // Guard the destroy: the remote can reset while it lands, and a Noise
      // stream erroring with no listener takes down the whole process.
      conn.on('error', () => {})
      try { conn.destroy() } catch (_) {}
      return
    }
    const remoteHex = info.publicKey ? b4a.toString(info.publicKey, 'hex') : 'anon'
    log.info('  + peer:', remoteHex.slice(0, 16))
    this.connections.set(conn, { lastActivity: Date.now() })

    // Attach our Protomux protocols to this connection
    try {
      if (this._seedProtocol) this._seedProtocol.attach(conn, info)
      if (this._circuitRelay) this._circuitRelay.attach(conn, info)
      if (this._proofOfRelay) this._proofOfRelay.attach(conn, info)
      if (this._serviceProtocol) this._serviceProtocol.attach(conn, info)
    } catch (err) {
      log.warn('  protocol attach error:', err.message)
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
    const existingApp = this.appRegistry?.has(appKeyHex) === true
    const admission = existingApp && this.storageAdmission?.recoveryReady && !this.storageAdmission?.fatalReason
      ? { allowed: true, availableBytes: this._storageAdmission(0).availableBytes }
      : this._storageAdmission(maxStorageBytes)
    const availableBytes = admission.availableBytes

    if (!admission.allowed) {
      log.warn('  seed rejected (insufficient storage):', appKeyHex.slice(0, 16))
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'insufficient storage' })
      deny('insufficient-storage', 'relay has ' + Math.max(0, availableBytes) + ' bytes available, request asked for ' + (msg.maxStorageBytes || 0))
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
      const appResult = await this.appLifecycle.seedApp(appKeyHex, {
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
      const newCoreKeys = []
      try {
        for (const dk of (msg.discoveryKeys || [])) {
          const keyHex = b4a.toString(dk, 'hex')
          if (keyHex === appKeyHex) continue
          const existed = this.seeder.cores.has(keyHex)
          await this.seeder.seedCore(keyHex, { maxStorageBytes })
          if (!existed) newCoreKeys.push(keyHex)
        }
      } catch (err) {
        for (const keyHex of newCoreKeys.reverse()) {
          try { await this.seeder.unseedCore(keyHex) } catch (_) {}
        }
        if (appResult.alreadySeeded !== true) {
          try { await this.appLifecycle.unseedApp(appKeyHex) } catch (_) {}
        }
        throw err
      }
    } catch (err) {
      log.warn('  seed error:', err.message)
      this.emit('seed-error', { appKey: appKeyHex, error: err })
      deny('storage-admission-blocked', err.message || 'durable storage admission failed')
      return
    }

    try {
      this._seedProtocol.acceptSeedRequest(
        msg.appKey,
        this.swarm.keyPair.publicKey,
        (this.config.regions && this.config.regions[0]) || 'unknown',
        this._storageAdmission(0).availableBytes
      )
    } catch (err) {
      try { this.emit('seed-ack-error', { appKey: appKeyHex, error: err }) } catch (_) {}
      return
    }
    log.info('  ✓ seeded:', appKeyHex.slice(0, 16))
    try { this.emit('seed-accepted', { appKey: appKeyHex, mode, publisherPubkey: effectivePublisher }) } catch (_) {}
  }

  _onUnseedRequest (msg) {
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

  // ─── Eviction (called by AppLifecycle when storage is full) ──────

  async _evictOldestApp () {
    let oldest = null
    for (const [key, entry] of this.appRegistry.apps) {
      if (!oldest || entry.startedAt < oldest.entry.startedAt) {
        oldest = { key, entry }
      }
    }
    if (oldest) {
      log.info('  evicting oldest app:', oldest.key.slice(0, 16))
      await this.appLifecycle.unseedApp(oldest.key)
      return true
    }
    return false
  }

  // Used by AppLifecycle for parent drive lookup (distributed-drive compat).
  // In Bare mode we don't bridge distributed-drive, so return null.
  get distributedDriveBridge () { return null }
}

// Re-export so pear-entry.js can do:
//   import { BareRelay } from './core/relay-node/bare-relay.js'
export default BareRelay
