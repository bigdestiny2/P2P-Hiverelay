/**
 * HiveRelay Client SDK
 *
 * Drop-in module for Pear apps. Handles relay discovery, content
 * publishing, replication, seeding, and NAT traversal — all behind
 * the scenes. The developer gets a simple publish/open/get API.
 * The end user never sees relay infrastructure.
 *
 * Simple usage (auto-creates everything):
 *
 *   import { HiveRelayClient } from 'p2p-hiverelay-client'
 *
 *   const app = new HiveRelayClient('./my-app-storage')
 *   await app.start()
 *
 *   const drive = await app.publish([
 *     { path: '/index.html', content: '<h1>Hello</h1>' }
 *   ])
 *   console.log('Share this key:', drive.key.toString('hex'))
 *
 *   // On another device:
 *   const remote = await app.open(key)
 *   const html = await app.get(key, '/index.html')
 *
 * Advanced usage (bring your own swarm):
 *
 *   const app = new HiveRelayClient({ swarm, store })
 *   await app.start()
 */

import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import Protomux from 'protomux'
import c from 'compact-encoding'
import { Duplex } from 'streamx'
import sodium from 'sodium-universal'
import hypercoreCrypto from 'hypercore-crypto'
import { createRevocation } from 'p2p-hiverelay/core/delegation.js'
import { createSeedingManifest, verifySeedingManifest } from 'p2p-hiverelay/core/seeding-manifest.js'
import { selectQuorum, describeQuorum } from 'p2p-hiverelay/core/quorum-selector.js'
import { ForkDetector } from 'p2p-hiverelay/core/fork-detector.js'
import { verifyCapabilityDoc } from 'p2p-hiverelay/core/capability-doc.js'
import { signForkProof } from 'p2p-hiverelay/core/fork-proof-signing.js'
import { EventEmitter } from 'events'
import { readdir, readFile, writeFile, lstat, mkdir, rename, rm } from 'fs/promises'
import { join, relative, resolve, dirname } from 'path'
import { BootstrapCache } from 'p2p-hiverelay/core/bootstrap-cache.js'
import { verifyAccountingReceipt } from 'p2p-hiverelay/core/protocol/accounting-receipt.js'
import {
  PROOF_KIND_RETRIEVABILITY,
  RETRIEVABILITY_PROOF_LIMITATION,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE,
  verifyStorageProof
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'
import {
  SEED_REQUEST_SIGNATURE_DOMAIN,
  serializeSeedRequestForDomainSigning
} from 'p2p-hiverelay/core/protocol/seed-request.js'
import {
  seedRequestEncoding,
  seedAcceptEncoding,
  unseedRequestEncoding,
  seedDenyEncoding,
  relayReserveEncoding
} from 'p2p-hiverelay/core/protocol/messages.js'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'
import { serviceMessageEncoding } from 'p2p-hiverelay/core/services/protocol.js'
import {
  MAX_FORWARD_DATA_MSG_BYTES,
  forwardOpenEncoding,
  forwardDataEncoding,
  forwardStatusEncoding,
  forwardCloseEncoding
} from 'p2p-hiverelay/core/protocol/forward-relay.js'
import {
  circuitConnectEncoding,
  circuitDataEncoding,
  circuitStatusEncoding,
  circuitReadyEncoding,
  circuitCloseEncoding
} from 'p2p-hiverelay/core/protocol/relay-circuit.js'
import {
  RELAY_DISCOVERY_TOPIC,
  DISCOVERY_EPOCH_MS,
  syncEpochDiscoveryTopics,
  SEED_PROTOCOL_NAME,
  CIRCUIT_PROTOCOL_NAME,
  FORWARD_PROTOCOL_NAME,
  SERVICES_PROTOCOL_NAME
} from 'p2p-hiverelay/core/constants.js'
import { attachPairing, deriveTopic as _deriveTopic, generateCode as _generateCode, proofFor as _proofFor } from './pairing.js'
// PVSS blind-custody orchestration composes the SELF-CONTAINED client modules
// (Bare-safe; @noble + sodium + b4a) — never core's custody-signing/pvss, which
// the frozen p2p-hiverelay@0.7.2 pin does not carry. Cross-impl agreement with
// the relay verifier is pinned by test (client-custody-crossimpl.test.js).
import {
  createCustodyIntent as _createCustodyIntent,
  createCustodyCommit as _createCustodyCommit,
  computeReceiptRoot as _computeReceiptRoot,
  hashHex as _custodyHashHex
} from './custody.js'
import {
  split as _pvssSplit,
  decryptShare as _pvssDecryptShare,
  reconstruct as _pvssReconstruct
} from './secret-sharing.js'

function portableTmpdir () {
  const env = (typeof globalThis.process !== 'undefined' && globalThis.process.env) ||
    (typeof globalThis.Bare !== 'undefined' && globalThis.Bare.env) ||
    {}
  return env.TMPDIR || env.TMP || env.TEMP || '/tmp'
}

// Re-exports for test/inspection use. Not part of the stable public surface.
export const _pairing = {
  deriveTopic: _deriveTopic,
  generateCode: _generateCode,
  proofFor: _proofFor
}

const FORWARD_MAX_FRAME = MAX_FORWARD_DATA_MSG_BYTES
const CORE_RETRIEVABILITY_HTTP_FEATURE = 'retrievability-proof-http'
const TRACKED_PUBLISH_LANE = Symbol('tracked-publish-lane')
const TRACKED_SEED_LANE = Symbol('tracked-seed-lane')

/**
 * Parse the total object size out of an HTTP Content-Range header
 * ("bytes 0-0/12345" → 12345). Returns null when absent/unparseable.
 * @param {string|null} value
 * @returns {number|null}
 */
function parseContentRangeTotal (value) {
  if (typeof value !== 'string') return null
  const m = value.match(/\/(\d+)\s*$/)
  if (!m) return null
  const n = Number(m[1])
  return Number.isFinite(n) ? n : null
}

// Internal/test-visible cancellation boundary for client.open(). A successful
// drive update must clear its losing timeout; a timeout must also detach the
// Hypercore upgrade request before open() continues with a partially-known
// drive. This mirrors the relay-side cancellable update contract without
// coupling the standalone client package to RelayNode lifecycle code.
export async function _waitForDriveUpdate (drive, timeoutMs) {
  const activeRequests = []
  const core = drive?.db?.core || drive?.core || null
  let timer = null
  const clearActive = (error) => {
    if (activeRequests.length === 0) return
    if (core?.replicator && typeof core.replicator.clearRequests === 'function') {
      try { core.replicator.clearRequests(activeRequests, error) } catch {}
    }
    activeRequests.length = 0
  }

  try {
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        const error = new Error('Drive update timed out')
        clearActive(error)
        reject(error)
      }, timeoutMs)
      Promise.resolve()
        .then(() => drive.update({ wait: true, activeRequests }))
        .then(resolve, reject)
    })
  } finally {
    if (timer) clearTimeout(timer)
    clearActive(new Error('Drive update settled'))
  }
}

export class HiveRelayClient extends EventEmitter {
  /**
   * @param {string|object} storageOrOpts - Storage path string, or options object
   * @param {object} opts - Options (when first arg is a string)
   *
   * When storageOrOpts is a string:
   *   Creates its own Corestore + Hyperswarm automatically.
   *
   * When storageOrOpts is an object:
   *   { swarm, store, keyPair, autoDiscover, maxRelays, ... }
   *   Uses the provided swarm/store (advanced mode).
   */
  constructor (storageOrOpts, opts = {}) {
    super()

    let config = opts
    if (typeof storageOrOpts === 'string') {
      // Simple mode: just a storage path
      config = { storage: storageOrOpts, ...opts }
    } else if (storageOrOpts && typeof storageOrOpts === 'object') {
      // Advanced mode: options object (may include swarm/store)
      config = { ...storageOrOpts, ...opts }
    }

    this._ownsSwarm = !config.swarm
    this._ownsStore = !config.store
    this._keyPairExplicit = !!config.keyPair
    this._storagePath = config.storage || null

    this.store = config.store || null
    this.swarm = config.swarm || null
    this.keyPair = config.keyPair || (this.swarm && this.swarm.keyPair) || null
    // Ephemeral read identity: when true, the swarm (the identity a relay
    // actually sees on the wire) gets a FRESH random keypair every session,
    // decoupled from any stable signing keyPair above. A read-only consumer
    // therefore presents an unlinkable identity per session, so a relay
    // operator can't stitch a consumer's fetches together over time. Off by
    // default to preserve existing stable-identity callers (allowlists,
    // reputation); read clients that want unlinkability set { ephemeral: true }.
    // Note: a client that supplies its OWN swarm controls that swarm's keypair,
    // so this flag only applies when the client owns the swarm.
    this.ephemeral = config.ephemeral === true
    // Look up epoch-rotated discovery buckets in addition to the static topic.
    // Defaults on for ephemeral read clients (they already want privacy); any
    // client can force it with { discoverEpochTopics: true }.
    this._discoverEpochTopics = config.discoverEpochTopics === true || this.ephemeral
    this._epochDiscoveryTimer = null
    this._epochDiscoveryTopics = new Map()
    this._retiringDiscoveryHandles = new Set()
    this._driveDiscoveryHandles = new Map()
    this._shareBundleCores = new Map()
    this._operations = new Set()
    this._openingDrives = new Map()
    this._provisionalPublishDrives = new Map()
    this._ownerOperations = new WeakMap()
    this._lifecycleAbort = null
    this.autoDiscover = config.autoDiscover !== false
    this.maxRelays = config.maxRelays || 10
    this.connectionTimeout = config.connectionTimeout || 10_000
    this._destroyTimeout = config.destroyTimeout || 15_000
    this.bootstrap = config.bootstrap || null

    // Relay tracking
    this.relays = new Map() // pubkey hex -> { conn, info, channels, connectedAt }
    this.seedRequests = new Map() // appKey hex -> { request, acceptances }
    this.reservations = new Map() // relay pubkey hex -> { reservation }

    // Drive management
    this.drives = new Map() // key hex -> Hyperdrive
    this._appDrives = new Map() // appId string -> key hex (persistent app→drive mapping)
    this._appDriveMappingTail = Promise.resolve()
    this._publishTails = new Map()
    this._seedTails = new Map()

    // Seed defaults
    this.autoSeed = config.autoSeed !== false
    this.seedReplicas = config.seedReplicas || 3
    this.seedTimeout = config.seedTimeout || 10_000

    this._started = false
    this._starting = null
    this._destroying = null
    this._stopping = false
    this._discoveryTopic = null
    this._reconnect = { timer: null, delay: 5000, attempt: 0 }
    this._relayHealthInterval = null
    this._relayScores = new Map() // pubkeyHex -> { latency: number, successes: number, failures: number, bytesServed: number, connectedSince: number }
    this._registry = null

    // Service RPC state
    this._pendingServiceRequests = new Map() // requestId -> { resolve, reject, timer }
    this._serviceRequestId = 1
    // Live service-event subscriptions: `${relayPubkey}|${topic}` -> Set<onEvent>.
    // One MSG_SUBSCRIBE per (relay,topic) is sent for the first local listener;
    // MSG_UNSUBSCRIBE when the last one detaches.
    this._serviceSubscriptions = new Map()

    // Persistent seed retry queue
    // Stored at {storagePath}/pending-seeds.json; survives process restart.
    this._pendingSeeds = new Map() // appKey hex -> { appKey, opts, enqueuedAt, attempts, lastAttempt, nextRetryAt, reason }
    this._pendingSeedSaveTail = Promise.resolve()
    this._pendingSeedTimers = new Map() // appKey hex -> setTimeout handle
    this._pendingSeedsLoaded = false
    this._pendingSeedConfig = {
      baseDelay: 30_000, // 30s
      maxDelay: 3_600_000, // 1h
      maxAttempts: 50
    }

    // ─── Quorum + fork-detection state (v0.6.0 security additions) ───
    //
    // Implements docs/THREAT-MODEL.md defense mechanisms #1 (replica
    // diversity) and #2 (fork detection). All state below is additive;
    // legacy code paths that don't call queryQuorum() / open() with the
    // new options keep working unchanged.
    //
    // Capability cache stores the last-fetched capability doc per relay
    // URL with a TTL — keeps quorum selection fast without repeated
    // network round-trips. Values: { doc, fetchedAt }
    this._capabilityCache = new Map()
    this._capabilityCacheTtl = config.capabilityCacheTtl || 5 * 60 * 1000
    // Foundation pubkeys — when supplied, the 'foundation' quorum
    // strategy uses this list as its trusted floor. Operators of-last-
    // resort live here. See docs/OPERATOR-INCENTIVES-Y1.md.
    this._foundationPubkeys = Array.isArray(config.foundationPubkeys)
      ? config.foundationPubkeys.map(s => String(s).toLowerCase())
      : []
    // Known-relay registry: URL → pinned pubkey. When the operator has
    // out-of-band knowledge of a relay's identity, pinning here means
    // the client auto-rejects fetched capability docs whose pubkey
    // doesn't match — the strongest defense against relay impersonation.
    // Foundation pubkeys are auto-registered if their URLs are known
    // via knownRelays config.
    this._knownRelays = new Map()
    if (config.knownRelays && typeof config.knownRelays === 'object') {
      for (const [url, pubkey] of Object.entries(config.knownRelays)) {
        if (typeof pubkey === 'string') {
          this._knownRelays.set(url.replace(/\/+$/, ''), pubkey.toLowerCase())
        }
      }
    }
    // ForkDetector is loaded lazily on start() so the class is usable
    // in test environments that don't call start().
    this.forkDetector = null
  }

  /**
   * Join the current + next epoch discovery buckets as a client (lookup only).
   * Idempotent; safe to call on a timer to roll across epoch boundaries.
   */
  _joinEpochDiscovery () {
    if (!this.swarm) return
    this._epochDiscoveryTopics = syncEpochDiscoveryTopics(
      this._epochDiscoveryTopics,
      this.swarm,
      { server: false, client: true },
      null,
      DISCOVERY_EPOCH_MS,
      (handle) => this._queueDiscoveryDestroy(handle)
    )
  }

  _trackOperation (operation) {
    const promise = Promise.resolve(operation)
    this._operations.add(promise)
    const cleanup = () => this._operations.delete(promise)
    promise.then(cleanup, cleanup)
    return promise
  }

  _queuePublishLane (lane, run) {
    const previous = this._publishTails.get(lane) || Promise.resolve()
    const operation = previous.catch(() => {}).then(run)
    const tail = operation.catch(() => {})
    this._publishTails.set(lane, tail)
    const cleanup = () => {
      if (this._publishTails.get(lane) === tail) this._publishTails.delete(lane)
    }
    tail.then(cleanup, cleanup)
    return operation
  }

  _queueSeedLane (keyHex, run) {
    const previous = this._seedTails.get(keyHex) || Promise.resolve()
    const operation = previous.catch(() => {}).then(run)
    const tail = operation.catch(() => {})
    this._seedTails.set(keyHex, tail)
    const cleanup = () => {
      if (this._seedTails.get(keyHex) === tail) this._seedTails.delete(keyHex)
    }
    tail.then(cleanup, cleanup)
    return operation
  }

  async _raceLifecycle (operation, timeoutMs, label) {
    const signal = this._lifecycleAbort?.signal
    let timer = null
    let onAbort = null
    try {
      await Promise.race([
        Promise.resolve(operation),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error(label + ' timed out')
            err.code = 'CLIENT_OPERATION_TIMEOUT'
            reject(err)
          }, timeoutMs)
        }),
        new Promise((_resolve, reject) => {
          onAbort = () => {
            const err = new Error(label + ' aborted')
            err.name = 'AbortError'
            err.code = 'ABORT_ERR'
            reject(err)
          }
          if (!signal || signal.aborted) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        })
      ])
    } finally {
      if (timer) clearTimeout(timer)
      if (onAbort && signal) signal.removeEventListener('abort', onAbort)
    }
  }

  async _drainOperations () {
    const pending = Promise.allSettled([...this._operations])
    let timer = null
    try {
      await Promise.race([
        pending,
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error('client operation drain timed out')
            err.code = 'CLIENT_OPERATION_DRAIN_TIMEOUT'
            reject(err)
          }, this._destroyTimeout)
        })
      ])
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  _ownerOperation (label, owner, run) {
    const existing = this._ownerOperations.get(owner)
    if (existing) {
      if (existing.label === label) return existing.operation
      return existing.operation.catch(() => {}).then(() => this._ownerOperation(label, owner, run))
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

  async _awaitOwnerOperation (label, owner, run, timeoutMs = this._destroyTimeout) {
    const operation = this._ownerOperation(label, owner, run)
    let timer = null
    try {
      return await Promise.race([
        operation,
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error(label + ' timed out')
            err.code = 'CLIENT_TEARDOWN_TIMEOUT'
            reject(err)
          }, timeoutMs)
        })
      ])
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  async _awaitLifecycleOwnerOperation (label, owner, run, timeoutMs) {
    const operation = this._ownerOperation(label, owner, run)
    const signal = this._lifecycleAbort?.signal
    let timer = null
    let onAbort = null
    try {
      return await Promise.race([
        operation,
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error(label + ' timed out')
            err.code = 'CLIENT_OPERATION_TIMEOUT'
            reject(err)
          }, timeoutMs)
        }),
        new Promise((_resolve, reject) => {
          if (!signal) return
          onAbort = () => {
            const err = new Error(label + ' aborted')
            err.name = 'AbortError'
            err.code = 'ABORT_ERR'
            reject(err)
          }
          if (signal.aborted) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        })
      ])
    } finally {
      if (timer) clearTimeout(timer)
      if (onAbort && signal) signal.removeEventListener('abort', onAbort)
    }
  }

  _queueDiscoveryDestroy (handle) {
    if (!handle || typeof handle.destroy !== 'function') return
    const entry = { id: randomNameSuffix(), handle, promise: null }
    this._retiringDiscoveryHandles.add(entry)
    const operation = this._ownerOperation(
      'queued-discovery-destroy:' + entry.id,
      handle,
      () => handle.destroy()
    )
    entry.promise = operation
    operation.then(
      () => this._retiringDiscoveryHandles.delete(entry),
      () => { entry.promise = null }
    )
  }

  _retainDiscoveryHandle (handle) {
    if (!handle || typeof handle.destroy !== 'function') return
    this._retiringDiscoveryHandles.add({ id: randomNameSuffix(), handle, promise: null })
  }

  _joinDriveDiscovery (keyHex, topic, opts) {
    const previous = this._driveDiscoveryHandles.get(keyHex)
    const handle = this.swarm.join(topic, opts)
    if (previous && previous !== handle) this._queueDiscoveryDestroy(previous)
    this._driveDiscoveryHandles.set(keyHex, handle)
    return handle
  }

  async _destroyDriveDiscovery (keyHex) {
    const handle = this._driveDiscoveryHandles.get(keyHex)
    if (!handle) return
    if (typeof handle.destroy === 'function') {
      await this._awaitOwnerOperation(
        `drive-discovery:${keyHex}`,
        handle,
        () => handle.destroy()
      )
    }
    if (this._driveDiscoveryHandles.get(keyHex) === handle) {
      this._driveDiscoveryHandles.delete(keyHex)
    }
  }

  async _failOpen (keyHex, drive, cause) {
    try {
      await this._destroyDriveDiscovery(keyHex)
      if (drive && typeof drive.close === 'function') {
        await this._awaitOwnerOperation(`drive:${keyHex}`, drive, () => drive.close())
      }
    } catch (teardownError) {
      // Preserve the exact owner for destroy() retry. Never lose a drive whose
      // discovery/core teardown may still be live.
      if (drive) this.drives.set(keyHex, drive)
      const failure = new Error('client open teardown did not settle')
      failure.code = 'CLIENT_OPEN_TEARDOWN_FAILED'
      failure.cause = teardownError
      failure.openCause = cause
      throw failure
    }
    this._removeDriveForkListeners(keyHex)
    throw cause
  }

  _createPublishDrive (store, key, opts) {
    return new Hyperdrive(store, key, opts)
  }

  _createOpenDrive (store, key, opts) {
    return new Hyperdrive(store, key, opts)
  }

  async _resolveLivePublishDrive (keyHex) {
    const opening = this._openingDrives.get(keyHex)
    if (opening) {
      try { await opening } catch (_) {}
      this._assertPublishActive()
    }
    return this.drives.get(keyHex) || null
  }

  _assertPublishActive () {
    if (!this._started || this._stopping || this._lifecycleAbort?.signal.aborted) {
      const err = new Error('client publish cancelled by lifecycle teardown')
      err.code = 'CLIENT_PUBLISH_CANCELLED'
      throw err
    }
  }

  async _closeProvisionalPublish (id, owner) {
    if (owner.keyHex) await this._destroyDriveDiscovery(owner.keyHex)
    await this._awaitOwnerOperation(
      `publish-drive:${id}`,
      owner.drive,
      () => owner.drive.close()
    )
    if (this._provisionalPublishDrives.get(id) === owner) {
      this._provisionalPublishDrives.delete(id)
    }
  }

  async _destroyProvisionalPublishes () {
    let firstError = null
    for (const [id, owner] of [...this._provisionalPublishDrives]) {
      try { await this._closeProvisionalPublish(id, owner) } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  _removeDriveForkListeners (keyHex) {
    if (!this._driveForkListeners || !this._driveForkListeners.has(keyHex)) return
    const { core, onTruncate, onVerifyError } = this._driveForkListeners.get(keyHex)
    try { core.removeListener('truncate', onTruncate) } catch (_) {}
    try { core.removeListener('verification-error', onVerifyError) } catch (_) {}
    this._driveForkListeners.delete(keyHex)
  }

  async _destroyDiscoveryHandles () {
    let firstError = null
    const settle = async (run) => {
      try { await run() } catch (err) { if (!firstError) firstError = err }
    }

    for (const entry of [...this._retiringDiscoveryHandles]) {
      await settle(async () => {
        if (entry.promise) {
          await this._awaitOwnerOperation('retiring-discovery:' + entry.id, entry, () => entry.promise)
        } else {
          await this._awaitOwnerOperation('retiring-discovery:' + entry.id, entry, () => entry.handle.destroy())
        }
        this._retiringDiscoveryHandles.delete(entry)
      })
    }
    for (const [key, handle] of [...this._epochDiscoveryTopics]) {
      await settle(async () => {
        if (handle && typeof handle.destroy === 'function') {
          await this._awaitOwnerOperation(`epoch-discovery:${key}`, handle, () => handle.destroy())
        }
        if (this._epochDiscoveryTopics.get(key) === handle) this._epochDiscoveryTopics.delete(key)
      })
    }
    for (const [key, handle] of [...this._driveDiscoveryHandles]) {
      await settle(async () => {
        if (handle && typeof handle.destroy === 'function') {
          await this._awaitOwnerOperation(`drive-discovery:${key}`, handle, () => handle.destroy())
        }
        if (this._driveDiscoveryHandles.get(key) === handle) this._driveDiscoveryHandles.delete(key)
      })
    }
    const main = this._discoveryTopic
    if (main) {
      await settle(async () => {
        if (typeof main.destroy === 'function') {
          await this._awaitOwnerOperation('main-discovery', main, () => main.destroy())
        }
        if (this._discoveryTopic === main) this._discoveryTopic = null
      })
    }
    if (firstError) throw firstError
  }

  async _destroyShareBundles () {
    let firstError = null
    for (const [key, entry] of [...this._shareBundleCores]) {
      let settled = true
      if (entry.discovery && typeof entry.discovery.destroy === 'function') {
        try {
          await this._awaitOwnerOperation(
            `share-discovery:${key}`,
            entry.discovery,
            () => entry.discovery.destroy()
          )
          entry.discovery = null
        } catch (err) {
          settled = false
          if (!firstError) firstError = err
        }
      }
      if (settled && entry.core && typeof entry.core.close === 'function') {
        try {
          await this._awaitOwnerOperation(`share-core:${key}`, entry.core, () => entry.core.close())
        } catch (err) {
          settled = false
          if (!firstError) firstError = err
        }
      }
      if (settled && this._shareBundleCores.get(key) === entry) {
        this._shareBundleCores.delete(key)
      }
    }
    if (firstError) throw firstError
  }

  _retainShareBundleOwner (key, owner) {
    let id = key || ('share-owner-' + randomNameSuffix())
    while (this._shareBundleCores.has(id) && this._shareBundleCores.get(id) !== owner) {
      id = key + ':' + randomNameSuffix()
    }
    this._shareBundleCores.set(id, owner)
    return id
  }

  async _closeTransientShareBundle (key, owner, operationCause = null) {
    try {
      if (owner.discovery && typeof owner.discovery.destroy === 'function') {
        await this._awaitOwnerOperation(
          `share-discovery:${key}`,
          owner.discovery,
          () => owner.discovery.destroy()
        )
        owner.discovery = null
      }
      if (owner.core && typeof owner.core.close === 'function') {
        await this._awaitOwnerOperation(`share-core:${key}`, owner.core, () => owner.core.close())
        owner.core = null
      }
    } catch (teardownCause) {
      this._retainShareBundleOwner(key, owner)
      const failure = new Error('share bundle lifecycle teardown did not settle')
      failure.code = 'CLIENT_SHARE_BUNDLE_TEARDOWN_FAILED'
      failure.operationCause = operationCause
      failure.teardownCause = teardownCause
      throw failure
    }
  }

  /**
   * Initialize everything and start discovering relay nodes.
   */
  start () {
    if (this._starting) return this._starting
    const operation = this._startLifecycle()
    const starting = operation.finally(() => {
      if (this._starting === starting) this._starting = null
    })
    this._starting = starting
    return starting
  }

  async _startLifecycle () {
    if (this._destroying) await this._destroying
    if (this._stopping) {
      const err = new Error('client teardown is still pending')
      err.code = 'CLIENT_TEARDOWN_PENDING'
      throw err
    }
    if (this._started) return this
    this._stopping = false
    try {
      return await this._start()
    } catch (startCause) {
      try {
        await this._rollbackFailedStart()
      } catch (teardownCause) {
        const failure = new Error('client startup teardown did not settle')
        failure.code = 'CLIENT_START_TEARDOWN_FAILED'
        failure.startCause = startCause
        failure.teardownCause = teardownCause
        throw failure
      }
      throw startCause
    }
  }

  async _start () {
    this._lifecycleAbort = new AbortController()
    // Create store if we own it (only when storage path was given)
    if (this._ownsStore && !this.store && this._storagePath) {
      this.store = new Corestore(this._storagePath)
    }
    if (this._ownsStore && this.store) {
      await this._awaitOwnerOperation('owned-store-ready', this.store, () => this.store.ready())
    }

    // Create swarm if we own it
    if (this._ownsSwarm && !this.swarm) {
      let bootstrap = this.bootstrap
      if (this._storagePath) {
        this._bootstrapCache = new BootstrapCache(this._storagePath)
        await this._bootstrapCache.load()
        bootstrap = this._bootstrapCache.merge(bootstrap)
      }
      const swarmOpts = { bootstrap }
      // Fresh, unlinkable per-session network identity for read clients.
      if (this.ephemeral) swarmOpts.keyPair = hypercoreCrypto.keyPair()
      this.swarm = new Hyperswarm(swarmOpts)
      if (this._bootstrapCache) {
        this._bootstrapCache.start(this.swarm)
      }
    }

    // Adopt the swarm identity as the signing identity ONLY when the caller
    // gave us no explicit keyPair. Under { ephemeral: true } this means the
    // signing identity is itself fresh per session (a read client signs
    // nothing load-bearing); a publisher that needs a stable identity passes
    // an explicit keyPair and should leave ephemeral off.
    if (!this.keyPair && this.swarm.keyPair) {
      this.keyPair = this.swarm.keyPair
    }

    // Wire replication for all connections
    this._connectionHandler = (conn, info) => {
      if (this.store) this.store.replicate(conn)
      this._onConnection(conn, info)
    }
    this.swarm.on('connection', this._connectionHandler)

    // Join discovery topic to find relay nodes
    if (this.autoDiscover) {
      this._discoveryTopic = this.swarm.join(RELAY_DISCOVERY_TOPIC, {
        server: false,
        client: true
      })
      // Also look up the epoch-rotated discovery buckets so we can find relays
      // that announce there (privacy-aware operators in additive/strict mode).
      // Client-only lookups — strictly additive, only widens relay coverage.
      // Enabled for ephemeral read clients, or explicitly via discoverEpochTopics.
      if (this._discoverEpochTopics) {
        this._joinEpochDiscovery()
        this._epochDiscoveryTimer = setInterval(
          () => { try { this._joinEpochDiscovery() } catch (_) {} },
          Math.max(60_000, Math.floor(DISCOVERY_EPOCH_MS / 2))
        )
        if (this._epochDiscoveryTimer.unref) this._epochDiscoveryTimer.unref()
      }
      // A handle-scoped flush is retained in the exact-owner lane. Timeout is
      // non-fatal, but later destroy remains serialized behind the real flush.
      if (typeof this._discoveryTopic.flushed === 'function') {
        const discovery = this._discoveryTopic
        try {
          await this._awaitLifecycleOwnerOperation(
            'main-discovery-flush',
            discovery,
            () => discovery.flushed(),
            500
          )
        } catch (err) {
          if (err?.name === 'AbortError' || err?.code === 'ABORT_ERR') throw err
        }
      }
    }

    // Start seeding registry for persistent seed request discovery
    if (this.store) {
      try {
        const registryStore = this.store.namespace('seeding-registry')
        const registry = new SeedingRegistry(registryStore, this.swarm)
        this._registry = registry
        await this._awaitOwnerOperation('registry-start', registry, () => registry.start())
      } catch (err) {
        this.emit('registry-error', { context: 'registry-start', error: err })
        const registry = this._registry
        if (registry) {
          try {
            await this._awaitOwnerOperation('registry-stop', registry, () => registry.stop())
            if (this._registry === registry) this._registry = null
          } catch (stopErr) {
            const failure = new Error('client seeding registry startup teardown did not settle')
            failure.code = 'CLIENT_REGISTRY_START_TEARDOWN_FAILED'
            failure.cause = stopErr
            failure.startCause = err
            throw failure
          }
        }
      }
    }

    if (this._stopping) {
      const err = new Error('client startup cancelled by destroy')
      err.code = 'CLIENT_START_CANCELLED'
      throw err
    }
    this._started = true
    this._startReconnectLoop()
    this._startRelayHealthChecks()

    // Load persistent seed retry queue and schedule retries
    await this._loadPendingSeeds()
    this._schedulePendingSeeds()

    // ─── ForkDetector — load any persisted equivocation evidence ────
    // Storage path may be null in advanced-mode (caller-supplied
    // store with no `storage` config); in that case the detector runs
    // in-memory only and forgets across restarts. Operators who care
    // about persistence will configure a storage path.
    if (this._storagePath) {
      this.forkDetector = new ForkDetector({
        storagePath: join(this._storagePath, 'forks.json')
      })
      try { await this.forkDetector.load() } catch (err) {
        this.emit('fork-detector-error', { context: 'load', error: err })
      }
      // Re-emit fork events on the client so applications can react.
      this.forkDetector.on('fork-detected', (info) => this.emit('fork-detected', info))
      this.forkDetector.on('fork-resolved', (info) => this.emit('fork-resolved', info))
    } else {
      this.forkDetector = new ForkDetector({})
    }

    this.emit('ready')
    this.emit('started')
    return this
  }

  async _rollbackFailedStart () {
    this._stopping = true
    if (this._lifecycleAbort) this._lifecycleAbort.abort()
    this._started = false
    if (this._relayHealthInterval) {
      clearInterval(this._relayHealthInterval)
      this._relayHealthInterval = null
    }
    if (this._reconnect.timer) {
      clearInterval(this._reconnect.timer)
      this._reconnect.timer = null
    }
    if (this._epochDiscoveryTimer) {
      clearInterval(this._epochDiscoveryTimer)
      this._epochDiscoveryTimer = null
    }
    if (this._replicationMonitors) {
      for (const [key, handle] of [...this._replicationMonitors]) {
        handle.stop()
        this._replicationMonitors.delete(key)
      }
    }
    for (const timer of this._pendingSeedTimers.values()) clearTimeout(timer)
    this._pendingSeedTimers.clear()
    if (this._operations.size > 0) await this._drainOperations()
    await this._awaitOwnerOperation(
      'pending-seeds-save',
      this,
      () => this._savePendingSeeds()
    )
    if (this._registry) {
      const registry = this._registry
      await this._awaitOwnerOperation('registry-stop', registry, () => registry.stop())
      if (this._registry === registry) this._registry = null
    }
    if (this._pairing) {
      const pairing = this._pairing
      await this._awaitOwnerOperation('pairing', pairing, () => pairing.destroy())
      if (this._pairing === pairing) this._pairing = null
    }
    if (this._connectionHandler && this.swarm) {
      this.swarm.removeListener('connection', this._connectionHandler)
      this._connectionHandler = null
    }
    for (const pending of this._pendingServiceRequests.values()) {
      clearTimeout(pending.timer)
      pending.reject(new Error('CLIENT_START_FAILED'))
    }
    this._pendingServiceRequests.clear()
    this._serviceSubscriptions.clear()
    await this._destroyDiscoveryHandles()
    await this._destroyShareBundles()
    await this._destroyProvisionalPublishes()
    for (const [keyHex] of [...this.drives]) await this.closeDrive(keyHex)
    if (this.forkDetector) {
      const detector = this.forkDetector
      await this._awaitOwnerOperation('fork-detector-save', detector, () => detector.save())
      detector.removeAllListeners()
      if (this.forkDetector === detector) this.forkDetector = null
    }
    if (this._bootstrapCache) {
      const cache = this._bootstrapCache
      cache.stop()
      await this._awaitOwnerOperation('bootstrap-cache-save', cache, () => cache.save())
      if (this._bootstrapCache === cache) this._bootstrapCache = null
    }
    if (this._ownsSwarm && this.swarm) {
      const swarm = this.swarm
      await this._awaitOwnerOperation('owned-swarm', swarm, () => swarm.destroy())
      if (this.swarm === swarm) this.swarm = null
    }
    if (this._ownsStore && this.store) {
      const store = this.store
      await this._awaitOwnerOperation('owned-store', store, () => store.close())
      if (this.store === store) this.store = null
    }
    if (this._ownsSwarm && !this._keyPairExplicit) this.keyPair = null
    this.relays.clear()
    this.seedRequests.clear()
    this.reservations.clear()
    this._capabilityCache.clear()
    this._lifecycleAbort = null
    this._stopping = false
  }

  // ─── Content API ─────────────────────────────────────────────────

  /**
   * Publish content to a Hyperdrive and request relay seeding.
   *
   * If opts.appId is provided, reuses an existing drive for that app
   * (version update) instead of creating a new one. This prevents
   * duplicate app entries on the relay network.
   *
   * @param {Array<{path: string, content: Buffer|string}>} files - Files to write
   * @param {object} opts
   * @param {string} opts.appId - Stable app identifier (e.g. 'pear-pos'). Reuses drive if one exists.
   * @param {string} opts.key - Explicit drive key hex to update (overrides appId lookup)
   * @param {boolean} opts.seed - Request seeding (default: this.autoSeed)
   * @param {number} opts.replicas - Number of relay replicas
   * @param {number} opts.timeout - Seed request timeout in ms
   * @returns {Promise<Hyperdrive>} The published drive
   */
  publish (filesOrDir, opts = {}) {
    return this._trackOperation(this._publishOwned(filesOrDir, opts))
  }

  async _publishOwned (filesOrDir, opts = {}) {
    this._ensureStarted()
    let drive = null
    let provisionalId = null
    let provisionalOwner = null
    let keyHex = null
    let published = false
    let borrowedDrive = false
    let mappingWriteAttempted = false
    let priorMemoryMapping = { present: false, key: null }
    let priorPersistedMapping = null

    try {
      // Support directory path: client.publish('./my-app') reads all files from disk
      let files
      if (typeof filesOrDir === 'string') {
        const dirPath = resolve(filesOrDir)
        files = await this._readDirectory(dirPath)
        this._assertPublishActive()
        if (files.length === 0) throw new Error('No files found in ' + dirPath)
        // Auto-derive appId from directory name if not set
        if (!opts.appId) {
          const dirName = dirPath.split('/').pop() || dirPath.split('\\').pop()
          opts.appId = dirName
        }
      } else {
        files = filesOrDir
      }

      // One client-level publish transaction owns drive-map promotion, app
      // mapping, observers, and rollback. A global lane deliberately trades
      // publish throughput for collision safety across mixed identities
      // ({appId,key}, key-only, or two appIds resolving to one drive key).
      const publishLane = 'client-publish'
      if (opts[TRACKED_PUBLISH_LANE] !== publishLane) {
        return await this._queuePublishLane(publishLane, () => this._publishOwned(files, {
          ...opts,
          [TRACKED_PUBLISH_LANE]: publishLane
        }))
      }

      let isUpdate = false

      priorMemoryMapping = opts.appId && this._appDrives.has(opts.appId)
        ? { present: true, key: this._appDrives.get(opts.appId) }
        : { present: false, key: null }

      // Capture disk authority before an explicit-key update can replace it.
      // The final commit can then restore the exact prior mapping if lifecycle
      // cancellation lands during its atomic write.
      if (opts.appId && this._storagePath) {
        priorPersistedMapping = await this._loadAppDriveMapping(opts.appId)
        this._assertPublishActive()
      }

      // Encryption key for blind mode (relay stores ciphertext, can't read content)
      const driveOpts = opts.encryptionKey ? { encryptionKey: opts.encryptionKey } : {}

      // Priority 1: explicit key (resume publishing to a known drive)
      if (opts.key) {
        const keyBuf = typeof opts.key === 'string' ? b4a.from(opts.key, 'hex') : opts.key
        const requestedKeyHex = b4a.toString(keyBuf, 'hex')
        drive = await this._resolveLivePublishDrive(requestedKeyHex)
        borrowedDrive = !!drive
        if (!drive) drive = this._createPublishDrive(this.store, keyBuf, driveOpts)
        isUpdate = true
      // Priority 2: appId lookup (reuse drive for same app)
      } else if (opts.appId && this._appDrives.has(opts.appId)) {
        const existingKey = this._appDrives.get(opts.appId)
        drive = await this._resolveLivePublishDrive(existingKey)
        borrowedDrive = !!drive
        if (!drive) drive = this._createPublishDrive(this.store, b4a.from(existingKey, 'hex'), driveOpts)
        isUpdate = true
      // Priority 3: check persisted app→drive mapping from storage
      } else if (opts.appId && priorPersistedMapping) {
        drive = await this._resolveLivePublishDrive(priorPersistedMapping)
        borrowedDrive = !!drive
        if (!drive) drive = this._createPublishDrive(this.store, b4a.from(priorPersistedMapping, 'hex'), driveOpts)
        isUpdate = true
      }

      // No existing drive found — create new with unique namespace
      // (avoids Corestore contention under active replication in Pear/Bare runtime)
      if (!drive) {
        const ns = this.store.namespace('drive-' + Date.now() + '-' + randomNameSuffix())
        drive = this._createPublishDrive(ns, null, driveOpts)
      }

      // Publish tentative ownership before drive.ready() can overlap teardown.
      // Failed cleanup retains this exact owner for rollback/destroy retry.
      if (!borrowedDrive) {
        provisionalId = 'publish-' + randomNameSuffix()
        provisionalOwner = { drive, keyHex: null }
        this._provisionalPublishDrives.set(provisionalId, provisionalOwner)
      }

      await drive.ready()
      this._assertPublishActive()
      keyHex = b4a.toString(drive.key, 'hex')
      if (provisionalOwner) provisionalOwner.keyHex = keyHex

      // Write all files to the drive
      for (const file of files) {
        const content = typeof file.content === 'string'
          ? b4a.from(file.content)
          : file.content
        await drive.put(file.path, content)
        this._assertPublishActive()
      }

      if (!borrowedDrive) {
        this._joinDriveDiscovery(keyHex, drive.discoveryKey, { server: true, client: true })
        this.drives.set(keyHex, drive)
      }
      published = true
      if (provisionalOwner && this._provisionalPublishDrives.get(provisionalId) === provisionalOwner) {
        this._provisionalPublishDrives.delete(provisionalId)
      }

      // Joining is sufficient for normal DHT announcement. Do not launch an
      // explicit background flush: Hyperswarm has no cancellation primitive,
      // so a losing timeout race could otherwise outlive client teardown.

      const shouldSeed = opts.seed !== undefined ? opts.seed : this.autoSeed
      if (shouldSeed) {
        const target = opts.replicas || this.seedReplicas
        const timeout = opts.timeout || this.seedTimeout
        try {
          const acceptances = await this.seed(drive.key, { replicas: target, timeout })
          // Attach the outcome directly to the drive so callers have a one-shot
          // view of "did my publish actually reach the target?" without a
          // follow-up call to getReplicationStatus().
          drive.replicas = {
            target,
            accepted: acceptances.length,
            healthy: acceptances.length >= target,
            relays: acceptances.map((a) => ({
              pubkey: a.relayPubkey ? b4a.toString(a.relayPubkey, 'hex') : null,
              region: a.region || null
            }))
          }
          this.emit('seeded', { key: keyHex, acceptances: acceptances.length, target })
        } catch (err) {
          drive.replicas = { target, accepted: 0, healthy: false, relays: [], error: err.message }
          this.emit('seed-error', { key: keyHex, error: err })
        }
        this._assertPublishActive()
      } else {
        drive.replicas = null // explicitly signal: caller opted out of seeding
      }

      this._assertPublishActive()
      // Commit the app mapping atomically after seed settlement. Any abort or
      // observer failure below restores the exact prior memory + disk mapping.
      if (opts.appId) {
        mappingWriteAttempted = true
        await this._saveAppDriveMapping(opts.appId, keyHex, { throwOnError: true })
        this._assertPublishActive()
        this._appDrives.set(opts.appId, keyHex)
      }
      this.emit('published', { key: keyHex, files: files.length, isUpdate, replicas: drive.replicas })
      return drive
    } catch (publishCause) {
      let mappingTeardownCause = null
      if (mappingWriteAttempted) {
        try {
          await this._saveAppDriveMapping(opts.appId, priorPersistedMapping, {
            throwOnError: true,
            expectedCurrentKey: keyHex
          })
        } catch (err) {
          mappingTeardownCause = err
        }
      }
      if (opts.appId && mappingWriteAttempted && this._appDrives.get(opts.appId) === keyHex) {
        if (priorMemoryMapping.present) this._appDrives.set(opts.appId, priorMemoryMapping.key)
        else this._appDrives.delete(opts.appId)
      }
      try {
        if (!borrowedDrive && published && keyHex && this.drives.get(keyHex) === drive) {
          await this._closeDriveOwned(keyHex)
        } else if (provisionalId && provisionalOwner) {
          await this._closeProvisionalPublish(provisionalId, provisionalOwner)
        }
      } catch (teardownCause) {
        const failure = new Error('client publish teardown did not settle')
        failure.code = 'CLIENT_PUBLISH_TEARDOWN_FAILED'
        failure.publishCause = publishCause
        failure.teardownCause = teardownCause
        failure.mappingTeardownCause = mappingTeardownCause
        throw failure
      }
      if (mappingTeardownCause) {
        const failure = new Error('client publish mapping rollback did not settle')
        failure.code = 'CLIENT_PUBLISH_MAPPING_ROLLBACK_FAILED'
        failure.publishCause = publishCause
        failure.mappingTeardownCause = mappingTeardownCause
        throw failure
      }
      throw publishCause
    }
  }

  /**
   * Open an existing Hyperdrive by key and replicate it.
   *
   * @param {string|Buffer} key - 64-char hex string or 32-byte Buffer
   * @param {object} opts
   * @param {boolean} opts.wait - Wait for initial update (default true)
   * @param {number} opts.timeout - How long to wait for first update in ms (default 15000)
   * @param {boolean} opts.seedAsReader - Volunteer to also serve this drive
   *   to other peers after opening it. Adds redundancy by making *every reader*
   *   a potential replica (Keet-style room redundancy applied to broadcast
   *   content). Defaults to false — opt-in because it has privacy and
   *   bandwidth implications: other peers will see this client's pubkey as a
   *   source for the drive, and this client will spend bandwidth serving the
   *   bytes onward.
   * @returns {Promise<Hyperdrive>} The opened drive
   */
  open (key, opts = {}) {
    const keyBuf = typeof key === 'string' ? b4a.from(key, 'hex') : key
    const keyHex = b4a.toString(keyBuf, 'hex')
    const publishing = this._publishTails.get('client-publish')
    if (publishing) return publishing.catch(() => {}).then(() => this.open(keyBuf, opts))
    if (this.drives.has(keyHex)) return Promise.resolve(this.drives.get(keyHex))
    if (this._openingDrives.has(keyHex)) return this._openingDrives.get(keyHex)
    const operation = this._trackOperation(this._open(keyBuf, opts))
    this._openingDrives.set(keyHex, operation)
    const cleanup = () => {
      if (this._openingDrives.get(keyHex) === operation) this._openingDrives.delete(keyHex)
    }
    operation.then(cleanup, cleanup)
    return operation
  }

  async _open (key, opts = {}) {
    this._ensureStarted()

    const keyBuf = typeof key === 'string' ? b4a.from(key, 'hex') : key
    const keyHex = b4a.toString(keyBuf, 'hex')

    // Quarantine check (v0.6.0 security): if the ForkDetector has
    // recorded an unresolved fork for this drive, refuse to open it
    // unless the caller explicitly passes { force: true }. Forks are
    // cryptographic equivocation evidence — opening a forked drive
    // means committing to ONE of the two divergent histories without
    // knowing which is canonical. Operators must resolve the fork
    // first (rotate keys / revoke / mark false-alarm).
    if (!opts.force && this.isDriveQuarantined(keyHex)) {
      const err = new Error(
        'Drive ' + keyHex + ' is quarantined: an unresolved fork is on record. ' +
        'Pass { force: true } to open anyway, or call client.forkDetector.resolve() first.'
      )
      err.code = 'DRIVE_QUARANTINED'
      err.driveKey = keyHex
      throw err
    }
    // Audit trail: if the operator bypassed quarantine via force:true,
    // record the event so an incident-response investigation later has
    // a chronological trail of overrides. The fork-detector persists
    // the log alongside fork records.
    if (opts.force && this.forkDetector && this.forkDetector.isQuarantined(keyHex)) {
      this.forkDetector.recordBypass({
        hypercoreKey: keyHex,
        caller: opts.caller || 'client.open',
        note: typeof opts.bypassReason === 'string' ? opts.bypassReason : null
      })
    }

    if (this.drives.has(keyHex)) {
      return this.drives.get(keyHex)
    }

    const driveOpts = opts.encryptionKey ? { encryptionKey: opts.encryptionKey } : {}
    const drive = this._createOpenDrive(this.store, keyBuf, driveOpts)
    try {
      await this._awaitLifecycleOwnerOperation(
        `drive-ready:${keyHex}`,
        drive,
        () => drive.ready(),
        opts.readyTimeout || this.connectionTimeout
      )
    } catch (err) {
      return this._failOpen(keyHex, drive, err)
    }

    // ─── Auto-detect forks during replication (Defect 2 fix) ────────
    //
    // Hypercore emits 'truncate' when the local view is rolled back
    // due to fork detection during replication — i.e. a peer served
    // blocks that conflict with what we already have. This is the
    // smoking gun for an equivocating publisher.
    //
    // We register the listener BEFORE the swarm.join below so we
    // catch the very first replication round that might trigger it.
    // The handler records evidence to the ForkDetector and emits the
    // event upward so callers can react (drop the drive, alert the
    // operator, etc.).
    if (drive.core && this.forkDetector && typeof drive.core.on === 'function') {
      const onTruncate = (newLength, fork) => {
        // The hypercore 'truncate' event fires with (newLength, fork).
        // 'fork' is the new fork id; if it changed, that's a fork.
        try {
          this.forkDetector.report({
            hypercoreKey: keyHex,
            blockIndex: typeof newLength === 'number' ? newLength : 0,
            evidenceA: { fromRelay: 'local', block: 'truncate-event-pre', signature: 'auto-detected-pre-' + Date.now() },
            evidenceB: { fromRelay: 'replication', block: 'truncate-event-post-fork-' + fork, signature: 'auto-detected-post-' + Date.now() }
          })
          this.emit('drive-fork-detected', { driveKey: keyHex, newLength, fork })
        } catch (_) { /* non-fatal — drive remains operational, fork is recorded */ }
      }
      const onVerifyError = (err) => {
        // Signature verification failure during replication. This is
        // less common than truncate but equally diagnostic.
        try {
          this.forkDetector.report({
            hypercoreKey: keyHex,
            blockIndex: 0,
            evidenceA: { fromRelay: 'expected', block: 'verified-prior-state', signature: 'expected-' + Date.now() },
            evidenceB: { fromRelay: 'replication', block: 'verification-error: ' + (err?.message || 'unknown'), signature: 'verify-error-' + Date.now() }
          })
          this.emit('drive-verification-error', { driveKey: keyHex, error: err })
        } catch (_) { /* non-fatal */ }
      }
      drive.core.on('truncate', onTruncate)
      drive.core.on('verification-error', onVerifyError)
      // Track listeners so we can remove them on close
      if (!this._driveForkListeners) this._driveForkListeners = new Map()
      this._driveForkListeners.set(keyHex, { core: drive.core, onTruncate, onVerifyError })
    }

    const isAuthor = drive.core?.writable || false
    // server=true if author OR if reader explicitly opted in via seedAsReader.
    // Default authors-only preserves prior behaviour for callers that didn't
    // ask for redundancy.
    const serveOnward = isAuthor || opts.seedAsReader === true
    try {
      const discovery = this._joinDriveDiscovery(keyHex, drive.discoveryKey, { server: serveOnward, client: true })
      if (discovery && typeof discovery.flushed === 'function') {
        await this._awaitLifecycleOwnerOperation(
          `drive-discovery-flush:${keyHex}`,
          discovery,
          () => discovery.flushed(),
          opts.discoveryTimeout || this.connectionTimeout
        )
      }
    } catch (err) {
      return this._failOpen(keyHex, drive, err)
    }
    if (opts.seedAsReader === true && !isAuthor) {
      if (!this._readerReplicas) this._readerReplicas = new Set()
      this._readerReplicas.add(keyHex)
      this.emit('reader-replica-joined', { key: keyHex })
    }

    const shouldWait = opts.wait !== false
    if (shouldWait) {
      const timeout = opts.timeout || 15000
      try {
        await _waitForDriveUpdate(drive, timeout)
      } catch (err) {
        this.emit('open-timeout', { key: keyHex, error: err })
      }
    }

    this.drives.set(keyHex, drive)
    this.emit('opened', { key: keyHex })
    return drive
  }

  /**
   * Read a file from an opened drive.
   */
  async get (driveKey, path) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const drive = this.drives.get(keyHex)
    if (!drive) throw new Error('Drive not open: ' + keyHex.slice(0, 12) + '...')
    return drive.get(path)
  }

  /**
   * Write a file to an owned drive.
   */
  async put (driveKey, path, content) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const drive = this.drives.get(keyHex)
    if (!drive) throw new Error('Drive not open: ' + keyHex.slice(0, 12) + '...')
    const buf = typeof content === 'string' ? b4a.from(content) : content
    await drive.put(path, buf)
  }

  /**
   * List files in a drive directory.
   */
  async list (driveKey, dir) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const drive = this.drives.get(keyHex)
    if (!drive) throw new Error('Drive not open: ' + keyHex.slice(0, 12) + '...')
    const entries = []
    const folder = dir || '/'
    try {
      for await (const entry of drive.list(folder)) {
        entries.push(entry.key)
      }
    } catch (err) {
      // Hypercore lifecycle errors during iteration (SESSION_CLOSED,
      // DECODING_ERROR, SNAPSHOT_NOT_AVAILABLE) are recoverable — the drive
      // closed mid-listing or a block was corrupted. Return what we have.
      this.emit('drive-list-error', { key: keyHex, dir: folder, error: err.message, code: err.code })
    }
    return entries
  }

  /**
   * Close a specific drive and leave its swarm topic.
   */
  closeDrive (driveKey) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    // Close is itself a publish-lane transaction. It therefore cannot be
    // overtaken by a publish queued after an earlier publish that close was
    // waiting on, and a later publish cannot borrow a drive mid-close.
    const operation = this._queuePublishLane(
      'client-publish',
      () => this._closeDriveOwned(keyHex)
    )
    return operation
  }

  async _closeDriveOwned (keyHex) {
    const opening = this._openingDrives.get(keyHex)
    if (opening) {
      try { await opening } catch (_) {}
    }
    const drive = this.drives.get(keyHex)
    if (!drive) return
    await this._destroyDriveDiscovery(keyHex)
    await this._awaitOwnerOperation(`drive:${keyHex}`, drive, () => drive.close())
    this._removeDriveForkListeners(keyHex)
    if (this.drives.get(keyHex) === drive) this.drives.delete(keyHex)
  }

  // ─── Relay API ───────────────────────────────────────────────────

  /**
   * Request seeding for a Hyperdrive/Hypercore key.
   * Broadcasts a signed seed request to all connected relays.
   *
   * @param {Buffer|string} appKey - 32-byte key or 64-char hex string
   * @param {object} opts - { replicas, region, maxStorage, ttlDays, timeout }
   * @returns {Promise<object[]>} Array of relay acceptances
   */
  seed (appKey, opts = {}) {
    return this._trackOperation(this._seedOwned(appKey, opts))
  }

  async _seedOwned (appKey, opts = {}) {
    this._assertPublishActive()
    const keyBuf = typeof appKey === 'string' ? b4a.from(appKey, 'hex') : appKey
    const keyHex = b4a.toString(keyBuf, 'hex')
    if (opts[TRACKED_SEED_LANE] !== keyHex) {
      return await this._queueSeedLane(keyHex, () => this._seedOwned(keyBuf, {
        ...opts,
        [TRACKED_SEED_LANE]: keyHex
      }))
    }

    // Hypercore/Hyperdrive discoveryKeys are a KEYED BLAKE2b of the pubkey
    // (key = the ASCII string "hypercore"), not a plain BLAKE2b hash.
    // Using a plain hash here meant the signed seed-request advertised a
    // discoveryKey on a completely different DHT topic than the actual
    // drive, so relays consuming `msg.discoveryKeys` looked in the wrong
    // place and never connected to the publisher. Callers can also pass
    // `opts.discoveryKey` to pin an explicit value (e.g. from drive.discoveryKey).
    const discoveryKey = opts.discoveryKey
      ? (typeof opts.discoveryKey === 'string' ? b4a.from(opts.discoveryKey, 'hex') : opts.discoveryKey)
      : hypercoreCrypto.discoveryKey(keyBuf)
    this._joinDriveDiscovery(keyHex, discoveryKey, { server: true, client: true })

    // Publisher commitments — all committed by the publisher signature so
    // a relay-side check can enforce them throughout the drive's lifetime.
    //
    //   opts.revocable        default true. Pass false to publish an
    //                         irrevocable commitment: only the operator
    //                         can later remove this content from their
    //                         relay; the publisher cannot.
    //   opts.unseedFreezeMs   default 0. Cooldown after seed before
    //                         publisher unseed is honored. "Commit then
    //                         think" buffer (e.g. 24h).
    //   opts.durability       default 0 (standard). Pass 1 for archive
    //                         tier — relays running v0.8+ AutoHeal will
    //                         maintain a diversity-enforced replica
    //                         fleet (≥7 replicas across ≥4 regions and
    //                         ≥5 distinct operators) by recruiting fresh
    //                         replicas as old ones drop out. Or pass the
    //                         string 'archive' for clarity.
    //   opts.seedSignatureDomain
    //                         default legacy v2 for mixed-version fleets.
    //                         Pass 'v3' or 'hiverelay.seed-request.v3' to
    //                         sign the preferred domain-separated preimage.
    //
    // All three fields are ignored by older relays, which behave as if
    // they were the permissive defaults.
    const revocable = opts.revocable !== false
    const unseedFreezeMs = Number.isFinite(opts.unseedFreezeMs) && opts.unseedFreezeMs > 0
      ? Math.floor(opts.unseedFreezeMs)
      : 0
    const durability = (opts.durability === 'archive' || opts.durability === 1)
      ? 1
      : 0

    // maxStorage default — see
    // docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md for the trap this
    // protects against: when a publisher leaves maxStorage at the SDK's
    // default while their drive grows over many releases, the relay
    // silently partial-pins (downloads metadata fully, stalls mid-blob),
    // and end users see indistinguishable-from-network-down hangs.
    //
    // Strategy:
    //   1. If opts.maxStorage is explicitly set, use it as-is and check
    //      it against the drive's current size (if we can see the drive)
    //      to catch the 256MB-cap-for-365MB-drive case loudly.
    //   2. If opts.maxStorage is missing, try to size-default from the
    //      local drive (drive.byteLength + drive.blobs?.core?.byteLength,
    //      times 4 for headroom). Falls back to 1 GB if we can't see
    //      the drive locally.
    let maxStorageBytes = opts.maxStorage
    if (!Number.isFinite(maxStorageBytes) || maxStorageBytes <= 0) {
      const observed = this._observedDriveSize(keyHex)
      if (observed > 0) {
        // 4× headroom — covers ~3-4 future releases at current growth.
        maxStorageBytes = Math.max(256 * 1024 * 1024, observed * 4)
      } else {
        // No local drive to size from — pick a default that's larger
        // than the historical 500MB so casual pins don't trip the bug.
        maxStorageBytes = 1024 * 1024 * 1024
      }
    } else {
      // Explicit cap — sanity-check against current drive size if we
      // can see it. Don't refuse (that'd break publishers who know what
      // they're doing) but warn loudly so they have a chance to fix it.
      const observed = this._observedDriveSize(keyHex)
      if (observed > 0 && observed > maxStorageBytes) {
        const recommended = Math.ceil(observed * 1.25)
        this.emit('seed-cap-warning', {
          appKey: keyHex,
          observedBytes: observed,
          declaredCap: maxStorageBytes,
          recommendedCap: recommended,
          hint: 'maxStorage is smaller than the drive\'s current byteLength; relays will silently partial-pin. Bump maxStorage to ≥ ' + recommended
        })
        if (typeof console !== 'undefined' && console.warn) {
          console.warn('[hiverelay-client] WARNING: maxStorage (' + maxStorageBytes + ') < drive size (' + observed + '); relays may silently partial-pin. Recommended cap: ' + recommended)
        }
      }
    }

    const request = {
      appKey: keyBuf,
      discoveryKeys: [discoveryKey],
      replicationFactor: opts.replicas || 3,
      geoPreference: opts.region ? [opts.region] : [],
      maxStorageBytes,
      bountyRate: 0,
      ttlSeconds: (opts.ttlDays || 30) * 24 * 3600,
      publisherPubkey: b4a.alloc(32),
      publisherSignature: b4a.alloc(64),
      revocable,
      unseedFreezeMs,
      durability
    }

    if (this.keyPair && this.keyPair.secretKey) {
      request.publisherPubkey = this.keyPair.publicKey
      const payload = this._useSeedSignatureDomainV3(opts)
        ? this._serializeForDomainSigning(request)
        : this._serializeForSigning(request)
      sodium.crypto_sign_detached(request.publisherSignature, payload, this.keyPair.secretKey)
    }

    const targetForEntry = opts.replicas || 3
    const floorForEntry = opts.floor != null ? opts.floor : Math.max(1, Math.floor(targetForEntry / 2))
    const entry = {
      request,
      acceptances: [],
      denials: [], // { relay, reasonCode, detail, terminal } per seedDeny received
      target: targetForEntry,
      floor: floorForEntry,
      lastSeedAt: Date.now()
    }
    this.seedRequests.set(keyHex, entry)

    // If no relays connected yet, wait briefly for discovery before broadcasting
    if (this.relays.size === 0 && this.autoDiscover) {
      await new Promise((resolve) => {
        const signal = this._lifecycleAbort?.signal
        let onAbort = null
        const done = () => {
          this.removeListener('relay-connected', onRelay)
          if (onAbort && signal) signal.removeEventListener('abort', onAbort)
          clearTimeout(t)
          resolve()
        }
        const onRelay = () => done()
        const t = setTimeout(done, 5000)
        onAbort = () => done()
        this.on('relay-connected', onRelay)
        if (signal?.aborted) onAbort()
        else if (signal) signal.addEventListener('abort', onAbort, { once: true })
      })
      this._assertPublishActive()
    }

    // Broadcast seed request via Protomux to all connected relays (instant path)
    const sendTime = Date.now()
    entry.sentAt = sendTime
    for (const relay of this.relays.values()) {
      if (relay.channels.seed) {
        relay.channels.seed.requestMsg.send(request)
      }
    }

    // Also publish to the distributed registry (persistent path — relays scanning later will find it)
    if (this._registry) {
      const registry = this._registry
      const registryOperationId = randomNameSuffix()
      try {
        await this._awaitLifecycleOwnerOperation(
          `registry-publish-request:${keyHex}:${registryOperationId}`,
          registry,
          () => registry.publishRequest(request),
          opts.registryTimeout || this.connectionTimeout
        )
      } catch (err) {
        if (err?.name === 'AbortError' || err?.code === 'ABORT_ERR') throw err
        this.emit('registry-error', { context: 'publish-request', error: err })
      }
      this._assertPublishActive()
    }

    // Re-broadcast to any relays that connect during the wait window
    const onNewRelay = (evt) => {
      const relay = this.relays.get(evt.pubkey)
      if (relay && relay.channels.seed) {
        relay.channels.seed.requestMsg.send(request)
      }
    }
    this.on('relay-connected', onNewRelay)
    try {
      this.emit('seed-request-published', { appKey: keyHex })

      const targetReplicas = opts.replicas || 3
      const timeout = opts.timeout || 15_000

      await new Promise((resolve) => {
        let timer = null
        const signal = this._lifecycleAbort?.signal
        let onAbort = null
        const done = () => {
          if (timer) clearTimeout(timer)
          this.removeListener('seed-accepted', check)
          this.removeListener('seed-denied', checkDenied)
          if (onAbort && signal) signal.removeEventListener('abort', onAbort)
          resolve()
        }
        const check = () => {
          if (entry.acceptances.length >= targetReplicas) done()
        }
        // Fast-fail: once every connected relay has terminally denied and
        // nothing accepted, waiting out the timeout buys nothing — resolve
        // now so the caller sees the denial reasons immediately instead of
        // an indistinguishable-from-network-down hang.
        const checkDenied = (evt) => {
          if (evt.appKey !== keyHex) return
          const terminalDenials = entry.denials.filter(d => d.terminal).length
          if (entry.acceptances.length === 0 && this.relays.size > 0 && terminalDenials >= this.relays.size) done()
        }
        this.on('seed-accepted', check)
        this.on('seed-denied', checkDenied)
        onAbort = () => done()
        timer = setTimeout(done, timeout)
        if (signal?.aborted) onAbort()
        else if (signal) signal.addEventListener('abort', onAbort, { once: true })
      })

      this._assertPublishActive()

      // Persistent retry: if we didn't get enough acceptances and the caller
      // didn't explicitly disable persistence, enqueue for retry across restarts.
      if (opts.retryPersistent !== false && entry.acceptances.length < targetReplicas) {
        // Carry any wire-level deny reasons into the retry record so the
        // shortfall is attributable (vs. an anonymous timeout).
        const denySummary = entry.denials.length > 0
          ? ';denied:' + entry.denials.map(d => d.reasonCode).join(',')
          : ''
        this._enqueuePendingSeed(keyHex, opts, `insufficient-acceptances:${entry.acceptances.length}/${targetReplicas}${denySummary}`)
      } else if (opts.retryPersistent !== false && entry.acceptances.length >= targetReplicas) {
        // Success — clear any existing pending retry for this key
        this._clearPendingSeed(keyHex, 'success')
      }

      return entry.acceptances
    } finally {
      this.removeListener('relay-connected', onNewRelay)
    }
  }

  /**
   * Look up the on-disk size of a drive we already know locally.
   *
   * Used by seed() to size-default maxStorage and to warn when an
   * explicit cap is smaller than the drive's current byteLength. Both
   * cases protect publishers from the silent partial-pin trap
   * (docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md): a too-small cap
   * causes relays to download metadata fully but stall mid-blob, with
   * no failure signal to the publisher.
   *
   * Returns the sum of metadata-core byteLength + blob-core byteLength
   * if we have the drive in this client's corestore. Returns 0 if we
   * don't (in which case seed() can't make a size-based recommendation).
   *
   * Best-effort + synchronous: we only check what's already loaded. We
   * don't call drive.ready() / .update() here because seed() is hot path
   * and we don't want to block on network I/O.
   */
  _observedDriveSize (keyHex) {
    try {
      // Try the cached Hyperdrive instances (drives we recently opened
      // for publish/get/put/etc.). These have up-to-date core byteLengths.
      for (const [, drive] of (this._driveCache || new Map())) {
        if (drive && drive.key && b4a.toString(drive.key, 'hex') === keyHex) {
          const metaBytes = (drive.db && drive.db.core && drive.db.core.byteLength) || 0
          const blobBytes = (drive.blobs && drive.blobs.core && drive.blobs.core.byteLength) || 0
          return metaBytes + blobBytes
        }
      }
      // Fallback: peek at the corestore's loaded cores by key. We don't
      // construct a fresh Hyperdrive here (that'd touch disk + network);
      // we only report a size if the cores are already in memory.
      if (this.store && typeof this.store.cores?.get === 'function') {
        const keyBuf = b4a.from(keyHex, 'hex')
        const metaCore = this.store.cores.get(b4a.toString(keyBuf, 'hex'))
        if (metaCore && Number.isFinite(metaCore.byteLength)) {
          return metaCore.byteLength
        }
      }
    } catch (_) {
      // Best-effort: any error here means we can't size, just return 0.
    }
    return 0
  }

  // ─── Persistent seed retry queue ──────────────────────────────────

  _pendingSeedsFile () {
    if (!this._storagePath) return null
    return join(this._storagePath, 'pending-seeds.json')
  }

  async _loadPendingSeeds () {
    const file = this._pendingSeedsFile()
    if (!file) { this._pendingSeedsLoaded = true; return }
    try {
      const raw = await readFile(file, 'utf-8')
      const list = JSON.parse(raw)
      if (Array.isArray(list)) {
        for (const entry of list) {
          if (entry && entry.appKey) this._pendingSeeds.set(entry.appKey, entry)
        }
      }
    } catch (_) {
      // Missing file or parse error — start with empty queue
    }
    this._pendingSeedsLoaded = true
  }

  _savePendingSeeds () {
    const operation = this._pendingSeedSaveTail.catch(() => {}).then(() => this._savePendingSeedsOwned())
    this._pendingSeedSaveTail = operation.catch(() => {})
    return operation
  }

  async _savePendingSeedsOwned () {
    const file = this._pendingSeedsFile()
    if (!file) return
    try {
      await mkdir(dirname(file), { recursive: true })
      const tmp = file + '.tmp'
      const data = JSON.stringify([...this._pendingSeeds.values()], null, 2)
      await writeFile(tmp, data, 'utf-8')
      await rename(tmp, file)
    } catch (err) {
      this.emit('pending-seeds-save-error', { error: err.message })
    }
  }

  _enqueuePendingSeed (appKey, opts, reason) {
    const existing = this._pendingSeeds.get(appKey)
    const attempts = existing ? existing.attempts + 1 : 1
    const delay = Math.min(
      this._pendingSeedConfig.baseDelay * Math.pow(2, attempts - 1),
      this._pendingSeedConfig.maxDelay
    )

    if (attempts > this._pendingSeedConfig.maxAttempts) {
      this._clearPendingSeed(appKey, 'max-attempts')
      this.emit('seed-pending-failed', { appKey, attempts, reason })
      return
    }

    const entry = {
      appKey,
      opts: { ...opts, retryPersistent: true },
      enqueuedAt: existing ? existing.enqueuedAt : Date.now(),
      attempts,
      lastAttempt: Date.now(),
      nextRetryAt: Date.now() + delay,
      reason
    }
    this._pendingSeeds.set(appKey, entry)
    this._trackOperation(this._savePendingSeeds()).catch(() => {})
    this._scheduleSinglePendingSeed(appKey)
    this.emit('seed-pending-enqueued', { appKey, attempts, nextRetryAt: entry.nextRetryAt })
  }

  _clearPendingSeed (appKey, reason = 'cleared') {
    if (this._pendingSeedTimers.has(appKey)) {
      clearTimeout(this._pendingSeedTimers.get(appKey))
      this._pendingSeedTimers.delete(appKey)
    }
    if (this._pendingSeeds.delete(appKey)) {
      this._trackOperation(this._savePendingSeeds()).catch(() => {})
      if (reason === 'cancelled') this.emit('seed-pending-cancelled', { appKey })
      else if (reason === 'success') this.emit('seed-pending-success', { appKey })
    }
  }

  _schedulePendingSeeds () {
    for (const appKey of this._pendingSeeds.keys()) {
      this._scheduleSinglePendingSeed(appKey)
    }
  }

  _scheduleSinglePendingSeed (appKey) {
    if (this._pendingSeedTimers.has(appKey)) {
      clearTimeout(this._pendingSeedTimers.get(appKey))
    }
    const entry = this._pendingSeeds.get(appKey)
    if (!entry) return

    const delay = Math.max(0, entry.nextRetryAt - Date.now())
    const timer = setTimeout(() => {
      this._pendingSeedTimers.delete(appKey)
      this._trackOperation(this._retryPendingSeed(appKey)).catch((err) => {
        this.emit('seed-pending-retry-error', { appKey, error: err.message })
      })
    }, delay)
    if (timer.unref) timer.unref()
    this._pendingSeedTimers.set(appKey, timer)
  }

  async _retryPendingSeed (appKey) {
    const entry = this._pendingSeeds.get(appKey)
    if (!entry) return
    this.emit('seed-pending-retry', { appKey, attempt: entry.attempts })
    try {
      // Pass retryPersistent:true so failures re-enqueue rather than swallowing
      await this.seed(appKey, { ...entry.opts, retryPersistent: true })
    } catch (err) {
      // seed() itself rarely throws — it resolves with acceptances.
      // On unexpected error, re-enqueue with bumped attempts.
      this._enqueuePendingSeed(appKey, entry.opts, 'exception:' + err.message)
    }
  }

  getPendingSeeds () {
    return [...this._pendingSeeds.values()]
  }

  cancelPendingSeed (appKey) {
    this._clearPendingSeed(appKey, 'cancelled')
  }

  async retryPendingSeedsNow () {
    const keys = [...this._pendingSeeds.keys()]
    for (const appKey of keys) {
      if (this._pendingSeedTimers.has(appKey)) {
        clearTimeout(this._pendingSeedTimers.get(appKey))
        this._pendingSeedTimers.delete(appKey)
      }
      await this._retryPendingSeed(appKey).catch(() => {})
    }
  }

  /**
   * Unseed an app from all connected relays (developer kill switch).
   * Signs an unseed request with the client's keypair to prove publisher ownership.
   * The relay verifies the signature matches the publisherPubkey stored at seed time.
   *
   * @param {Buffer|string} appKey - 32-byte key or 64-char hex string
   * @returns {Promise<{ relays: number }>} Number of relays the unseed was broadcast to
   */
  async unseed (appKey) {
    if (!this.keyPair || !this.keyPair.secretKey) {
      throw new Error('Cannot unseed without a keypair (publisher identity required)')
    }

    const keyBuf = typeof appKey === 'string' ? b4a.from(appKey, 'hex') : appKey
    const keyHex = b4a.toString(keyBuf, 'hex')
    const timestamp = Date.now()

    // Sign (appKey + 'unseed' + timestamp) with publisher's secret key
    const tsBuf = b4a.alloc(8)
    const tsView = new DataView(tsBuf.buffer, tsBuf.byteOffset)
    tsView.setBigUint64(0, BigInt(timestamp))

    const payload = b4a.concat([keyBuf, b4a.from('unseed'), tsBuf])
    const signature = b4a.alloc(64)
    sodium.crypto_sign_detached(signature, payload, this.keyPair.secretKey)

    // Broadcast unseed via Protomux to all connected relays
    let broadcastCount = 0
    for (const relay of this.relays.values()) {
      if (relay.channels.seed) {
        // Use the seed protocol's unseed message
        const channel = relay.channels.seed
        if (channel.unseedMsg) {
          channel.unseedMsg.send({
            appKey: keyBuf,
            timestamp,
            publisherPubkey: this.keyPair.publicKey,
            publisherSignature: signature
          })
          broadcastCount++
        }
      }
    }

    // Clean up local state
    this.seedRequests.delete(keyHex)

    this.emit('unseed-published', {
      appKey: keyHex,
      relays: broadcastCount,
      timestamp
    })

    return { relays: broadcastCount }
  }

  /**
   * Reserve a circuit relay slot for NAT traversal.
   */
  async reserveRelay (relayPubKey) {
    const keyHex = typeof relayPubKey === 'string'
      ? relayPubKey
      : b4a.toString(relayPubKey, 'hex')

    const relay = this.relays.get(keyHex)
    if (!relay || !relay.channels.circuit) {
      throw new Error('Relay not connected or circuit protocol not available')
    }

    const peerPubkey = this.keyPair ? this.keyPair.publicKey : b4a.alloc(32)

    relay.channels.circuit.reserveMsg.send({
      peerPubkey,
      maxDurationMs: 60 * 60 * 1000,
      maxBytes: 64 * 1024 * 1024
    })

    return new Promise((resolve) => {
      const onStatus = (msg) => {
        if (msg.code === 0) {
          this.reservations.set(keyHex, { relayPubKey: keyHex, grantedAt: Date.now() })
          this.emit('relay-reserved', { relay: keyHex })
          resolve(true)
        } else {
          resolve(false)
        }
        this.removeListener('_circuit-status-' + keyHex, onStatus)
      }
      this.on('_circuit-status-' + keyHex, onStatus)
      setTimeout(() => {
        this.removeListener('_circuit-status-' + keyHex, onStatus)
        resolve(false)
      }, this.connectionTimeout)
    })
  }

  /**
   * Connect to a peer through a relay node (NAT traversal).
   */
  async connectViaRelay (targetPubKey, relayPubKey) {
    let relayHex = relayPubKey
      ? (typeof relayPubKey === 'string' ? relayPubKey : b4a.toString(relayPubKey, 'hex'))
      : null

    if (!relayHex) {
      relayHex = this._selectBestRelay('circuit')
    }

    if (!relayHex) {
      throw new Error('No relay nodes available for circuit relay')
    }

    const relay = this.relays.get(relayHex)
    if (!relay || !relay.channels.circuit) {
      throw new Error('Selected relay not connected')
    }

    const targetBuf = typeof targetPubKey === 'string' ? b4a.from(targetPubKey, 'hex') : targetPubKey
    const sourceBuf = this.keyPair ? this.keyPair.publicKey : b4a.alloc(32)

    relay.channels.circuit.connectMsg.send({
      targetPubkey: targetBuf,
      sourcePubkey: sourceBuf
    })

    return new Promise((resolve) => {
      const onStatus = (msg) => {
        this.removeListener('_circuit-status-' + relayHex, onStatus)
        resolve(msg.code === 0)
      }
      this.on('_circuit-status-' + relayHex, onStatus)
      setTimeout(() => {
        this.removeListener('_circuit-status-' + relayHex, onStatus)
        resolve(false)
      }, this.connectionTimeout)
    })
  }

  /**
   * Forward-relay TRANSPORT: connect to `targetPubKey` THROUGH `relayPubKey`'s
   * forward service and return a Duplex stream of the relayed byte channel.
   * The relay dials the target on demand and byte-bridges (it sees transport
   * traffic — run your own Noise / a sealed payload on top for secrecy). Run
   * a NoiseSecretStream + Protomux/ServiceProtocol over the returned stream,
   * keyed by the RELAY's pubkey (the relay is your immediate peer).
   *
   * Onion: call connectViaForward(relay2, relay1) to get a stream to relay2
   * through relay1, run a forward client over THAT, and connectViaForward(
   * seller, relay2) over it — no single relay links you to the seller.
   *
   * v1: one forward per relay connection. Resolves to a Duplex, or null if
   * the relay has no forward channel / is busy / the open is rejected.
   * @returns {Promise<Duplex|null>}
   */
  async connectViaForward (targetPubKey, relayPubKey) {
    const relayHex = typeof relayPubKey === 'string' ? relayPubKey.toLowerCase() : b4a.toString(relayPubKey, 'hex')
    const relay = this.relays.get(relayHex)
    if (!relay || !relay.channels.forward) return null
    const fwd = relay.channels.forward
    if (fwd.busy) return null
    fwd.busy = true
    const target = typeof targetPubKey === 'string' ? b4a.from(targetPubKey, 'hex') : targetPubKey

    const ok = await new Promise((resolve) => {
      const onStatus = (msg) => { this.removeListener('_forward-status-' + relayHex, onStatus); resolve(msg.code === 0) }
      this.on('_forward-status-' + relayHex, onStatus)
      try { fwd.openMsg.send({ target }) } catch (_) { this.removeListener('_forward-status-' + relayHex, onStatus); resolve(false) }
      setTimeout(() => { this.removeListener('_forward-status-' + relayHex, onStatus); resolve(false) }, this.connectionTimeout)
    })
    if (!ok) { fwd.busy = false; return null }

    const onData = (msg) => { if (msg && msg.data) stream.push(msg.data) }
    const onClose = () => { try { stream.push(null) } catch (_) {} }
    this.on('_forward-data-' + relayHex, onData)
    this.on('_forward-closed-' + relayHex, onClose)
    const cleanup = () => {
      this.removeListener('_forward-data-' + relayHex, onData)
      this.removeListener('_forward-closed-' + relayHex, onClose)
      fwd.busy = false
    }
    const stream = new Duplex({
      write (data, cb) {
        try {
          for (let i = 0; i < data.length; i += FORWARD_MAX_FRAME) fwd.dataMsg.send({ data: data.subarray(i, Math.min(i + FORWARD_MAX_FRAME, data.length)) })
          cb()
        } catch (err) { cb(err) }
      },
      final (cb) { try { fwd.closeMsg.send({ reason: 0 }) } catch (_) {} ; cb() },
      destroy (cb) { try { fwd.closeMsg.send({ reason: 0 }) } catch (_) {} ; cleanup(); cb() }
    })
    return stream
  }

  /**
   * Send data through an established circuit. The relay forwards the
   * bytes to the other endpoint of the named circuit. Caller is
   * responsible for E2E encryption on top — the relay sees ciphertext
   * but could (in principle) tamper with framing, so peers MUST run
   * their own authenticated handshake (Noise, etc.) over this byte
   * channel before trusting anything.
   *
   * @param {string} relayPubKey - hex pubkey of the relay routing this circuit
   * @param {string} circuitId - hex circuitId from the circuit-ready event
   * @param {Uint8Array} data - payload (max 64 KB per call by default)
   * @returns {boolean} true if the message was sent, false if the
   *                    relay or its circuit channel isn't available
   */
  sendCircuitData (relayPubKey, circuitId, data) {
    const relayHex = typeof relayPubKey === 'string' ? relayPubKey : b4a.toString(relayPubKey, 'hex')
    const relay = this.relays.get(relayHex)
    if (!relay || !relay.channels.circuit || !relay.channels.circuit.dataMsg) return false

    const circuitIdBuf = typeof circuitId === 'string' ? b4a.from(circuitId, 'hex') : circuitId
    if (!circuitIdBuf || circuitIdBuf.byteLength !== 16) {
      throw new Error('circuitId must be 16 bytes (hex string or buffer)')
    }

    const payload = data instanceof Uint8Array ? data : b4a.from(data)
    try {
      relay.channels.circuit.dataMsg.send({ circuitId: circuitIdBuf, data: payload })
      return true
    } catch (_) {
      return false
    }
  }

  // ─── Status ──────────────────────────────────────────────────────

  /**
   * Get relay and drive status.
   */
  getRelays () {
    const list = []
    for (const [pubkey, relay] of this.relays) {
      list.push({
        pubkey,
        hasSeedProtocol: !!relay.channels.seed,
        hasCircuitProtocol: !!relay.channels.circuit,
        hasServiceProtocol: !!relay.channels.service,
        connectedAt: relay.connectedAt
      })
    }
    return list
  }

  /**
   * Get the cached service catalog from connected relays.
   * Catalogs are received via MSG_CATALOG on connect.
   */
  getServiceCatalog () {
    const catalogs = {}
    for (const [pubkey, relay] of this.relays) {
      if (relay.serviceCatalog) {
        catalogs[pubkey] = relay.serviceCatalog
      }
    }
    return catalogs
  }

  /**
   * Discover apps across the relays this client is connected to.
   *
   * The new model is per-relay: there is no global merged catalog. Each
   * relay maintains its own local catalog and the operator decides what's
   * in it. By default this method returns one row per (app, source-relay)
   * pair, tagged with the source relay's pubkey, so a UI can render a
   * "from relay X" badge alongside each app.
   *
   * For callers that want the old deduplicated view (one row per appKey,
   * with a `relays` array of pubkeys that host it), pass { groupBy: 'app' }.
   *
   * @param {object} [opts]
   * @param {'app'|null} [opts.groupBy] - 'app' for legacy merged shape, null (default) for per-source rows
   * @param {string} [opts.relay] - restrict to a single relay pubkey
   * @returns {Array<object>}
   */
  getAvailableApps ({ groupBy = null, relay = null } = {}) {
    if (groupBy === 'app') {
      // Legacy merged view (kept for backward compatibility).
      const appMap = new Map()
      for (const [pubkey, r] of this.relays) {
        if (relay && pubkey !== relay) continue
        const apps = r.seededApps || []
        for (const app of apps) {
          const existing = appMap.get(app.appKey)
          if (existing) {
            existing.relays.push(pubkey)
          } else {
            appMap.set(app.appKey, {
              appKey: app.appKey,
              appId: app.appId,
              version: app.version,
              discoveryKey: app.discoveryKey,
              blind: app.blind,
              relays: [pubkey]
            })
          }
        }
      }
      return Array.from(appMap.values())
    }

    // Default: one row per (app, source-relay) pair, tagged for badge UIs.
    const rows = []
    for (const [pubkey, r] of this.relays) {
      if (relay && pubkey !== relay) continue
      const apps = r.seededApps || []
      for (const app of apps) {
        rows.push({
          appKey: app.appKey,
          appId: app.appId,
          version: app.version,
          discoveryKey: app.discoveryKey,
          blind: app.blind,
          source: {
            relayPubkey: pubkey,
            // Federation flags get populated when the relay advertises its
            // /catalog.json federation section to the client (future hook).
            mirrored: false,
            republished: false
          }
        })
      }
    }
    return rows
  }

  /**
   * Group per-source app rows by appKey. Convenience for UIs that want to
   * show "this app is on N relays" while still keeping per-relay attribution
   * available in `sources`.
   *
   * @returns {Array<{appKey, appId, version, discoveryKey, blind, sources: Array}>}
   */
  getAvailableAppsBySource () {
    const map = new Map()
    for (const row of this.getAvailableApps()) {
      const existing = map.get(row.appKey)
      if (existing) {
        existing.sources.push(row.source)
      } else {
        map.set(row.appKey, {
          appKey: row.appKey,
          appId: row.appId,
          version: row.version,
          discoveryKey: row.discoveryKey,
          blind: row.blind,
          sources: [row.source]
        })
      }
    }
    return Array.from(map.values())
  }

  getSeedStatus (appKey) {
    const keyHex = typeof appKey === 'string' ? appKey : b4a.toString(appKey, 'hex')
    const entry = this.seedRequests.get(keyHex)
    if (!entry) return null
    return {
      appKey: keyHex,
      acceptances: entry.acceptances.length,
      relays: entry.acceptances.map((a) => ({
        pubkey: b4a.toString(a.relayPubkey, 'hex'),
        region: a.region
      }))
    }
  }

  /**
   * Volunteer to serve a drive this client only opened as a reader. The
   * drive must already be opened (via `open()` or `publish()`). Idempotent.
   *
   * Privacy: other peers will see this client's swarm pubkey as a source for
   * the drive's discoveryKey. For sensitive content, prefer ephemeral
   * keypairs per session.
   *
   * Bandwidth: this client will be asked to serve the drive's bytes to other
   * peers. Use `disableReaderReplica()` or `closeDrive()` to stop.
   *
   * @param {string|Buffer} driveKey
   */
  enableReaderReplica (driveKey) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const drive = this.drives.get(keyHex)
    if (!drive) throw new Error('Drive not open: ' + keyHex.slice(0, 12) + '...')
    if (drive.core?.writable) return false // author already serves
    this._joinDriveDiscovery(keyHex, drive.discoveryKey, { server: true, client: true })
    if (!this._readerReplicas) this._readerReplicas = new Set()
    if (this._readerReplicas.has(keyHex)) return false
    this._readerReplicas.add(keyHex)
    this.emit('reader-replica-joined', { key: keyHex })
    return true
  }

  /**
   * Stop serving a drive that was previously opted in as a reader-replica.
   * Does nothing if this drive was authored by the local client (authors
   * always serve their own content while published).
   */
  disableReaderReplica (driveKey) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const drive = this.drives.get(keyHex)
    if (!drive) return false
    if (drive.core?.writable) return false
    if (!this._readerReplicas?.has(keyHex)) return false
    // Re-join as client-only to drop the server announcement.
    this._joinDriveDiscovery(keyHex, drive.discoveryKey, { server: false, client: true })
    this._readerReplicas.delete(keyHex)
    this.emit('reader-replica-left', { key: keyHex })
    return true
  }

  /**
   * List drives this client is currently serving onward as a reader-replica.
   */
  getReaderReplicas () {
    return Array.from(this._readerReplicas || [])
  }

  /**
   * Named verb for the Keet-style "I want to help seed this" pattern.
   * Equivalent to `open(driveKey, { ...opts, seedAsReader: true })` — opens
   * the drive AND volunteers to serve it onward. Clearer call-site intent
   * than the opts bag.
   *
   * @param {string|Buffer} driveKey
   * @param {object} [opts]  Same options as open() (encryptionKey, wait, timeout)
   * @returns {Promise<Hyperdrive>}
   */
  async mirror (driveKey, opts = {}) {
    return this.open(driveKey, { ...opts, seedAsReader: true })
  }

  /**
   * Stop serving a drive that was previously mirrored. Equivalent to
   * `disableReaderReplica(driveKey)`.
   */
  unmirror (driveKey) {
    return this.disableReaderReplica(driveKey)
  }

  // ─── Community replicas ─────────────────────────────────────────────
  //
  // The "users volunteer to help seed their favourite app's public drives"
  // pattern. The app developer pre-registers which drives are eligible
  // (by key + metadata); the user opts in once with `enableCommunityReplicas()`
  // and the client mirrors every registered drive automatically. Drives the
  // developer later adds to the manifest also pick up (if the user is opted
  // in) via `_autoMirrorCommunity`.
  //
  // This does NOT persist the user's opt-in across restarts — apps that
  // want that should store the preference themselves and call
  // `enableCommunityReplicas()` again on startup.

  /**
   * App-side: declare which drives this app invites its users to help seed.
   * Each entry: `{ driveKey, label?, encryptionKey?, description? }`.
   * Safe to call multiple times; subsequent calls merge with existing entries
   * (later entries override on matching driveKey).
   *
   * @param {Array<object>} drives
   */
  registerCommunityReplicas (drives) {
    if (!Array.isArray(drives)) throw new Error('registerCommunityReplicas: drives must be an array')
    if (!this._communityReplicas) this._communityReplicas = new Map()
    for (const entry of drives) {
      if (!entry || typeof entry.driveKey !== 'string' || entry.driveKey.length !== 64) {
        throw new Error('registerCommunityReplicas: each entry needs a 64-hex driveKey')
      }
      this._communityReplicas.set(entry.driveKey, {
        driveKey: entry.driveKey,
        label: entry.label || null,
        description: entry.description || null,
        encryptionKey: entry.encryptionKey || null
      })
    }
    // If the user was already opted in, auto-mirror any newly-added drives.
    if (this._communityOptedIn) {
      this._trackOperation(this._autoMirrorCommunity()).catch((err) => this.emit('community-replica-error', err))
    }
  }

  /**
   * App-side: inspect the current manifest.
   */
  getCommunityReplicas () {
    return Array.from((this._communityReplicas || new Map()).values())
  }

  /**
   * User-side: opt into helping seed the drives the app has registered.
   * By default mirrors every registered drive; pass `{ driveKey }` to opt
   * in to a single drive only.
   *
   * Returns `{ mirrored, failed }` where `mirrored` is the list of drive
   * keys we successfully joined and `failed` is the list that errored.
   */
  async enableCommunityReplicas (opts = {}) {
    if (!this._started) throw new Error('Client not started — call await app.start() first')
    if (!this._communityReplicas || this._communityReplicas.size === 0) {
      return { mirrored: [], failed: [] }
    }
    const only = opts.driveKey || null
    const entries = only
      ? [this._communityReplicas.get(only)].filter(Boolean)
      : Array.from(this._communityReplicas.values())

    const mirrored = []
    const failed = []
    for (const entry of entries) {
      try {
        await this.mirror(entry.driveKey, {
          encryptionKey: entry.encryptionKey || undefined,
          wait: false
        })
        mirrored.push(entry.driveKey)
        this.emit('community-replica-joined', { driveKey: entry.driveKey, label: entry.label })
      } catch (err) {
        failed.push({ driveKey: entry.driveKey, error: err.message })
        this.emit('community-replica-error', { driveKey: entry.driveKey, error: err })
      }
    }
    // Only mark as opted-in if at least one mirror succeeded; this way the
    // first successful call unlocks auto-mirror for later registrations.
    if (mirrored.length > 0) this._communityOptedIn = true
    return { mirrored, failed }
  }

  /**
   * User-side: stop mirroring community drives. Pass `{ driveKey }` to
   * drop a single one, or no arg to drop all.
   */
  disableCommunityReplicas (opts = {}) {
    if (!this._communityReplicas) return { disabled: [] }
    const only = opts.driveKey || null
    const keys = only
      ? [only]
      : Array.from(this._communityReplicas.keys())
    const disabled = []
    for (const k of keys) {
      if (this.unmirror(k)) disabled.push(k)
    }
    if (!only) this._communityOptedIn = false
    return { disabled }
  }

  /**
   * Internal: mirror any registered-but-not-yet-joined drives. Called when
   * a user is already opted in and the app registers additional drives.
   */
  async _autoMirrorCommunity () {
    if (!this._communityReplicas || !this._communityOptedIn) return
    const already = new Set(this.getReaderReplicas())
    for (const entry of this._communityReplicas.values()) {
      if (already.has(entry.driveKey)) continue
      try {
        await this.mirror(entry.driveKey, {
          encryptionKey: entry.encryptionKey || undefined,
          wait: false
        })
        this.emit('community-replica-joined', { driveKey: entry.driveKey, label: entry.label })
      } catch (err) {
        this.emit('community-replica-error', { driveKey: entry.driveKey, error: err })
      }
    }
  }

  /**
   * Replication status for an appKey, framed as the operational math
   * apps should be reasoning about. The Keet-style "always-on" property
   * is N×uptime — if your content is on N independent relays each with
   * decent uptime, your effective availability approaches 100% fast.
   *
   * Health bands (assuming target=3, floor=1):
   *   - healthy  : current >= target
   *   - degraded : floor < current < target
   *   - critical : current <= floor (re-broadcast a seed request)
   *
   * @param {string|Buffer} appKey
   * @returns {object|null}
   */
  getReplicationStatus (appKey) {
    const keyHex = typeof appKey === 'string' ? appKey : b4a.toString(appKey, 'hex')
    const entry = this.seedRequests.get(keyHex)
    if (!entry) return null
    const current = entry.acceptances.length
    const target = entry.target ?? 3
    const floor = entry.floor ?? Math.max(1, Math.floor(target / 2))
    let health
    if (current >= target) health = 'healthy'
    else if (current > floor) health = 'degraded'
    else health = 'critical'
    return {
      appKey: keyHex,
      current,
      target,
      floor,
      health,
      lastSeedAt: entry.lastSeedAt || null,
      relays: entry.acceptances.map((a) => ({
        pubkey: b4a.toString(a.relayPubkey, 'hex'),
        region: a.region
      }))
    }
  }

  /**
   * Distinguish "seed-request accepted" from "drive is actually replicating".
   *
   * An accepted seed request means the relay signed "yes I'll seed this" and
   * sent it back. It does NOT mean the relay has connected to the publisher
   * or pulled any bytes. In degraded network conditions, or when the
   * publisher's announce hasn't propagated through the DHT, a relay can
   * accept and then never actually connect. Callers who want "durable pin
   * confirmed" must check BOTH the acceptance count and the drive's live
   * hypercore peers.
   *
   * Returns:
   * {
   *   appKey,
   *   acceptances,          // from seedRequests — how many relays said "yes"
   *   activePeers,          // from drive.core.peers — how many are replicating *now*
   *   durable,              // heuristic: at least one active peer + some acceptance
   *   driveOpen,            // whether we have the drive loaded locally
   *   byteLengthLocal,      // local core length
   *   byteLengthRemoteMax   // max remoteLength across active peers (≥ local means synced)
   * }
   *
   * @param {string|Buffer} driveKey
   * @returns {object|null}
   */
  getDurableStatus (driveKey) {
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const entry = this.seedRequests.get(keyHex)
    const acceptances = entry ? entry.acceptances.length : 0
    const drive = this.drives.get(keyHex)

    if (!drive) {
      return {
        appKey: keyHex,
        acceptances,
        activePeers: 0,
        durable: false,
        driveOpen: false,
        byteLengthLocal: 0,
        byteLengthRemoteMax: 0
      }
    }

    const peers = (drive.core && drive.core.peers) || []
    const activePeers = peers.length
    const byteLengthLocal = drive.core ? (drive.core.length || 0) : 0
    let byteLengthRemoteMax = 0
    for (const p of peers) {
      const rl = p && p.remoteLength ? p.remoteLength : 0
      if (rl > byteLengthRemoteMax) byteLengthRemoteMax = rl
    }

    return {
      appKey: keyHex,
      acceptances,
      activePeers,
      // "durable" heuristic: at least one remote peer has reached our local
      // length (or beyond). That means someone has the bytes. Stronger than
      // "acceptance count > 0" but weaker than "N independent replicas all
      // caught up" — apps with a stricter bar should check the per-peer
      // breakdown themselves.
      durable: activePeers > 0 && byteLengthRemoteMax >= byteLengthLocal,
      driveOpen: true,
      byteLengthLocal,
      byteLengthRemoteMax
    }
  }

  /**
   * Block until a drive reaches "durable" state (or a timeout). Useful for
   * apps that want to confirm "my publish actually pinned" before they
   * consider the operation done — which acceptance alone doesn't guarantee.
   *
   * @param {string|Buffer} driveKey
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=30000]
   * @param {number} [opts.pollIntervalMs=500]
   * @param {number} [opts.minPeers=1]
   * @returns {Promise<object>} the final getDurableStatus() snapshot
   */
  async waitForDurable (driveKey, opts = {}) {
    const timeoutMs = opts.timeoutMs || 30000
    const pollMs = opts.pollIntervalMs || 500
    const minPeers = opts.minPeers || 1
    const deadline = Date.now() + timeoutMs
    let status = this.getDurableStatus(driveKey)
    while (Date.now() < deadline) {
      status = this.getDurableStatus(driveKey)
      if (status.durable && status.activePeers >= minPeers) return status
      await new Promise((resolve) => setTimeout(resolve, pollMs))
    }
    return status
  }

  /**
   * Aggregate replication picture across every appKey this client has seeded.
   * Useful for a dashboard / status panel.
   */
  getReplicationOverview () {
    const apps = []
    let healthy = 0
    let degraded = 0
    let critical = 0
    for (const keyHex of this.seedRequests.keys()) {
      const status = this.getReplicationStatus(keyHex)
      if (!status) continue
      apps.push(status)
      if (status.health === 'healthy') healthy++
      else if (status.health === 'degraded') degraded++
      else critical++
    }
    return {
      totalApps: apps.length,
      healthy,
      degraded,
      critical,
      apps
    }
  }

  /**
   * Start a background monitor that periodically checks replication for the
   * given appKey and re-broadcasts the seed request if current drops to or
   * below the floor. Idempotent: calling again on the same key resets the
   * interval. Returns a stop() handle.
   *
   * The monitor is opt-in — clients that publish content and don't care
   * about availability beyond the initial seed don't pay the cost.
   *
   * @param {string|Buffer} appKey
   * @param {object} [opts]
   * @param {number} [opts.checkInterval=300000] - ms between checks (default 5 min)
   * @param {number} [opts.replicas] - re-uses entry.target if not set
   * @returns {{stop: Function}}
   */
  enableReplicationMonitor (appKey, opts = {}) {
    const keyHex = typeof appKey === 'string' ? appKey : b4a.toString(appKey, 'hex')
    if (!this._replicationMonitors) this._replicationMonitors = new Map()
    const existing = this._replicationMonitors.get(keyHex)
    if (existing) existing.stop()

    const interval = opts.checkInterval || 5 * 60 * 1000
    let stopped = false
    const tick = async () => {
      if (stopped || !this._started) return
      const status = this.getReplicationStatus(keyHex)
      if (!status) return
      if (status.current <= status.floor) {
        try {
          await this.seed(keyHex, {
            replicas: opts.replicas || status.target,
            timeout: opts.timeout || 10_000
          })
          this.emit('replication-rebroadcast', { appKey: keyHex, before: status.current, target: status.target })
        } catch (err) {
          this.emit('replication-error', { appKey: keyHex, error: err.message })
        }
      }
    }

    const timer = setInterval(tick, interval)
    if (timer.unref) timer.unref()

    const handle = {
      stop: () => {
        if (stopped) return
        stopped = true
        clearInterval(timer)
        // Only remove from the map if we're still the live handle for this
        // key. Otherwise an old handle's stop() would wipe a newer monitor
        // installed via enableReplicationMonitor() being called again.
        if (this._replicationMonitors.get(keyHex) === handle) {
          this._replicationMonitors.delete(keyHex)
        }
      }
    }
    this._replicationMonitors.set(keyHex, handle)
    return handle
  }

  getStatus () {
    if (!this._started) return { started: false }
    return {
      started: true,
      relays: this.getRelays(),
      drives: this.drives.size,
      connections: this.swarm ? this.swarm.connections.size : 0
    }
  }

  // ─── Multi-device pairing ─────────────────────────────────────────
  //
  // The Keet "always-on" trick #2: same identity, multiple devices. If a
  // user runs the app on phone + laptop, either one being online keeps
  // their published content available.
  //
  // Two paths are supported:
  //
  //   (a) Identity sharing — exportIdentity / importIdentity. Both devices
  //       hold the same private key. Simplest; both devices indistinguishable
  //       on the wire. Best for "this is my second device, full trust."
  //
  //   (b) Device attestation — primary device signs a delegation cert for a
  //       secondary device's pubkey. The secondary device publishes with its
  //       own key but ships the delegation alongside. Allows TTL + revocation
  //       without rotating the primary identity. Verification is client-side
  //       today; relay-side verification is future work (the relay
  //       seed-request protocol would have to carry the cert).

  /**
   * Serialize this client's identity keypair into a transferable bundle.
   *
   * SECURITY: the bundle contains the raw private key. Treat it like a
   * password — transfer over a private channel (QR code with the device
   * physically present, an out-of-band encrypted message, etc.). Don't
   * email it or paste in chat.
   *
   * @returns {{publicKey: string, secretKey: string, version: number}}
   */
  exportIdentity () {
    if (!this.keyPair || !this.keyPair.secretKey) {
      throw new Error('No identity keypair to export')
    }
    return {
      version: 1,
      publicKey: b4a.toString(this.keyPair.publicKey, 'hex'),
      secretKey: b4a.toString(this.keyPair.secretKey, 'hex')
    }
  }

  /**
   * Replace this client's identity with a previously-exported bundle.
   * After import, this client publishes under the imported identity —
   * other peers see this device as the same publisher as the source.
   *
   * @param {object} bundle - The output of exportIdentity()
   */
  importIdentity (bundle) {
    if (!bundle || bundle.version !== 1) throw new Error('Invalid identity bundle (unsupported version)')
    if (!bundle.publicKey || !bundle.secretKey) throw new Error('Invalid identity bundle (missing keys)')
    const publicKey = b4a.from(bundle.publicKey, 'hex')
    const secretKey = b4a.from(bundle.secretKey, 'hex')
    if (publicKey.length !== 32) throw new Error('Invalid identity bundle (publicKey not 32 bytes)')
    if (secretKey.length !== 64) throw new Error('Invalid identity bundle (secretKey not 64 bytes)')
    this.keyPair = { publicKey, secretKey }
    this.emit('identity-imported', { publicKey: bundle.publicKey })
  }

  /**
   * Sign a delegation cert authorising another device's pubkey to publish
   * on behalf of this identity. The secondary device ships this cert with
   * its own signed messages so verifiers can check the chain.
   *
   * @param {string|Buffer} otherPubkey - The secondary device's Ed25519 pubkey
   * @param {object} [opts]
   * @param {number} [opts.ttlMs=2592000000] - 30 days default
   * @param {string} [opts.label] - Optional human-readable label ('iPhone', 'Backup laptop')
   * @returns {{primaryPubkey, devicePubkey, expiresAt, label, signature, version}}
   */
  createDeviceAttestation (otherPubkey, opts = {}) {
    if (!this.keyPair || !this.keyPair.secretKey) throw new Error('No identity to attest from')
    const devicePk = typeof otherPubkey === 'string' ? b4a.from(otherPubkey, 'hex') : otherPubkey
    if (devicePk.length !== 32) throw new Error('otherPubkey must be 32 bytes')
    const ttl = opts.ttlMs || 30 * 24 * 60 * 60 * 1000
    const expiresAt = Date.now() + ttl
    const label = opts.label || ''

    // Signed payload: primaryPubkey || devicePubkey || expiresAt(8 bytes BE) || label
    const expBuf = b4a.alloc(8)
    new DataView(expBuf.buffer, expBuf.byteOffset).setBigUint64(0, BigInt(expiresAt), false)
    const labelBuf = b4a.from(label, 'utf8')
    const payload = b4a.concat([this.keyPair.publicKey, devicePk, expBuf, labelBuf])
    const signature = b4a.alloc(64)
    sodium.crypto_sign_detached(signature, payload, this.keyPair.secretKey)

    return {
      version: 1,
      primaryPubkey: b4a.toString(this.keyPair.publicKey, 'hex'),
      devicePubkey: b4a.toString(devicePk, 'hex'),
      expiresAt,
      label,
      signature: b4a.toString(signature, 'hex')
    }
  }

  /**
   * Verify a device attestation cert. Static method (no client state needed
   * to verify — anyone with the cert can check it).
   *
   * @param {object} cert - Output of createDeviceAttestation()
   * @returns {{valid: boolean, reason?: string}}
   */
  static verifyDeviceAttestation (cert) {
    try {
      if (!cert || cert.version !== 1) return { valid: false, reason: 'unsupported version' }
      if (Date.now() > cert.expiresAt) return { valid: false, reason: 'expired' }

      const primaryPk = b4a.from(cert.primaryPubkey, 'hex')
      const devicePk = b4a.from(cert.devicePubkey, 'hex')
      const sig = b4a.from(cert.signature, 'hex')
      if (primaryPk.length !== 32 || devicePk.length !== 32 || sig.length !== 64) {
        return { valid: false, reason: 'malformed' }
      }

      const expBuf = b4a.alloc(8)
      new DataView(expBuf.buffer, expBuf.byteOffset).setBigUint64(0, BigInt(cert.expiresAt), false)
      const labelBuf = b4a.from(cert.label || '', 'utf8')
      const payload = b4a.concat([primaryPk, devicePk, expBuf, labelBuf])

      const ok = sodium.crypto_sign_verify_detached(sig, payload, primaryPk)
      return ok ? { valid: true } : { valid: false, reason: 'bad signature' }
    } catch (err) {
      return { valid: false, reason: err.message }
    }
  }

  /**
   * Create a signed revocation for a previously-issued device attestation.
   * Only the primary device (the one with the primary secret key) can make
   * a valid revocation — other identities' "revocations" fail signature
   * verification on the relay side.
   *
   * The returned revocation can be POSTed to any relay's
   * `/api/manage/delegation/revoke` endpoint; that relay will stop
   * accepting seed requests that use the revoked cert. Revocations are
   * not auto-federated in this version — the operator broadcasts to the
   * relays they care about.
   *
   * @param {object} cert - The cert being revoked (output of createDeviceAttestation)
   * @param {object} [opts]
   * @param {string} [opts.reason]
   * @returns {object} Revocation message
   */
  createCertRevocation (cert, opts = {}) {
    if (!this.keyPair || !this.keyPair.secretKey) {
      throw new Error('No identity to sign revocation from')
    }
    if (!cert || typeof cert.primaryPubkey !== 'string') {
      throw new Error('Invalid cert')
    }
    // The primary pubkey on the cert must match this client's identity —
    // otherwise we're trying to revoke a cert we didn't issue.
    const myPub = b4a.toString(this.keyPair.publicKey, 'hex')
    if (cert.primaryPubkey.toLowerCase() !== myPub.toLowerCase()) {
      throw new Error('createCertRevocation: this identity did not issue the given cert')
    }
    // Delegate to the shared primitive (same one relays verify with).
    return createRevocation(cert, this.keyPair.secretKey, opts)
  }

  // ─── Seeding manifest (author-published relay list) ───────────────
  //
  // Authors sign a small "these are the relays you should fetch my drives
  // from" document. Clients discover it over plain HTTP (GET
  // /api/authors/<pubkey>/seeding.json), use it to decide which relays to
  // connect to for a given author's content.
  //
  // The fetch helpers also double as a relay-health probe: you can hit
  // /.well-known/hiverelay.json on any HiveRelay node to learn its version,
  // accept policy, and feature set without opening a Hyperswarm connection.

  /**
   * Build + sign a seeding manifest using this client's identity.
   *
   * @param {object} args
   * @param {Array}  args.relays - [{url, role: 'primary'|'backup'|'mirror'}]
   * @param {Array}  args.drives - [{driveKey, channel?}]
   * @param {number} [args.timestamp] - ms epoch (for tests); defaults to now
   * @returns {object} signed manifest ready to publish
   */
  createSeedingManifest ({ relays, drives, timestamp } = {}) {
    if (!this.keyPair) throw new Error('createSeedingManifest: client has no identity')
    return createSeedingManifest({ keyPair: this.keyPair, relays, drives, timestamp })
  }

  /**
   * Publish a signed seeding manifest to a HiveRelay node over HTTP. The
   * manifest must already be signed — use createSeedingManifest() first.
   * Accepts either a full URL (http://host:port) or a bare host:port pair.
   *
   * Returns {ok, pubkey, replaced} on success, throws on any failure so
   * callers can decide whether to retry against a different relay.
   *
   * @param {string} relayUrl   e.g. 'http://relay.example.com:9100'
   * @param {object} manifest   signed manifest from createSeedingManifest()
   * @returns {Promise<{ok: true, pubkey: string, replaced: boolean}>}
   */
  async publishSeedingManifest (relayUrl, manifest) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('publishSeedingManifest: relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const endpoint = base + '/api/authors/seeding.json'
    const res = await _fetchJson(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(manifest)
    })
    if (!res.ok) {
      const err = new Error('publishSeedingManifest failed: ' + (res.body?.error || res.status))
      err.status = res.status
      err.body = res.body
      throw err
    }
    return res.body
  }

  /**
   * Fetch a seeding manifest for `pubkey` from `relayUrl`. Returns the
   * manifest (with signature verified) on success, null on 404. Throws on
   * network or signature-verification failure so callers distinguish
   * "no manifest cached" (expected) from "relay is broken" (not expected).
   *
   * @param {string} relayUrl
   * @param {string} pubkey - hex (64 chars)
   * @returns {Promise<object|null>}
   */
  // ─── Atomic Blind Custody ──────────────────────────────────────────
  // Apps drive the custody pipeline through these methods. The relay
  // signs entries with its own keypair (blind custody), so the app
  // doesn't need to ship a publisher key. Each method posts to a
  // /api/custody/... endpoint that requires the relay's API key.

  /**
   * Publish a custody intent — the source's signed declaration that it
   * wants N replicas of an encrypted ciphertext root. Returns the signed
   * intent including its `intentId`, which the app uses to watch quorum
   * progress and sign the eventual commit.
   *
   * @param {string} relayUrl  base relay URL (https://relay.example:9100)
   * @param {object} intent    fields per docs/atomic-network-design.md
   * @param {object} opts      { apiKey } for relay auth
   * @returns {Promise<object>} signed custody-intent
   */
  async publishCustodyIntent (relayUrl, intent, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/intent', intent, opts)
  }

  /**
   * Publish a custody commit — declares quorum reached + receipt root +
   * optional next authority. Must come after recordCustodyReceipt has
   * accumulated `requiredReplicas` valid receipts.
   */
  async publishCustodyCommit (relayUrl, intentId, commit = {}, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/' + encodeURIComponent(intentId) + '/commit', commit, opts)
  }

  /**
   * Publish a source-retired entry — the publisher relinquishes future
   * authority over this content's custody state. Required before clients
   * can treat the handoff as durable.
   */
  async publishSourceRetired (relayUrl, intentId, retirement = {}, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/' + encodeURIComponent(intentId) + '/source-retired', retirement, opts)
  }

  /**
   * Record a custody-proof — an observer (or the publisher) attests that
   * a relay passed a ciphertext-block challenge. Useful for ongoing
   * audits. Body fields: relayPubkey, challengeNonce, shardIds,
   * blockIndices, passed, latencyMs, observerPubkey.
   */
  async recordCustodyProof (relayUrl, proof, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/proof', proof, opts)
  }

  /**
   * Record a custody-non-serving-proof — the relay attests it has stopped
   * serving content after retainUntil (catalog absent, swarm not serving,
   * gateway returns not-found).
   */
  async recordCustodyNonServingProof (relayUrl, intentId, proof = {}, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/' + encodeURIComponent(intentId) + '/non-serving-proof', proof, opts)
  }

  /**
   * Record a custody-expiry-witness tombstone — an independent third
   * party attests that the relay has stopped serving. Used in M-of-N
   * witness quorum policies for high-integrity expiry guarantees.
   */
  async recordCustodyExpiryWitness (relayUrl, intentId, witness = {}, opts = {}) {
    return this._postCustody(relayUrl, '/api/custody/' + encodeURIComponent(intentId) + '/witness', witness, opts)
  }

  /**
   * Get the current custody status for an intent — quorum count, commit
   * status, proofs received, etc. Read-only, no auth required.
   */
  async getCustodyStatus (relayUrl, intentId) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('getCustodyStatus: relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const endpoint = base + '/api/custody/' + encodeURIComponent(intentId) + '/status'
    const res = await _fetchJson(endpoint, { method: 'GET' })
    if (res.status === 404) return null
    if (!res.ok) {
      const err = new Error('getCustodyStatus failed: ' + (res.body?.error || res.status))
      err.status = res.status
      throw err
    }
    return res.body
  }

  async _postCustody (relayUrl, path, body, opts = {}) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const headers = { 'Content-Type': 'application/json' }
    // RelayAPI._checkAuth (packages/core/core/relay-node/api.js) reads ONLY
    // `req.headers.authorization` and requires `Bearer <key>`. The previous
    // X-API-Key header was silently ignored by every v0.8.x relay; no SDK
    // call to a custody POST endpoint with apiKey would ever authenticate.
    if (opts.apiKey) headers.Authorization = 'Bearer ' + opts.apiKey
    const res = await _fetchJson(base + path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body || {})
    })
    if (!res.ok) {
      const err = new Error('custody endpoint failed: ' + (res.body?.error || res.status))
      err.status = res.status
      err.body = res.body
      throw err
    }
    return res.body
  }

  /**
   * Ask a relay to seed the custody addressKey under a signed intent it has
   * already been handed (publishCustodyIntent). Seeding is what drives the
   * relay's PVSS share verification + receipt anchoring (core seedApp →
   * _recordCustodyReceipt). The relay re-fetches the signed intent by
   * custodyIntentId to learn its assigned shareIndex, the share scheme, and the
   * shareBundleKey it must replicate + verify against — so only the binding
   * fields are sent here; nothing secret. Authenticated: /seed requires a
   * Bearer API key (opts.apiKey).
   */
  async _seedForCustody (relayUrl, intent, opts = {}) {
    if (!Number.isSafeInteger(opts.maxStorage) || opts.maxStorage <= 0) {
      throw new Error('_seedForCustody: opts.maxStorage must be a positive safe integer')
    }
    const body = {
      appKey: intent.addressKey,
      maxStorageBytes: opts.maxStorage,
      blind: true,
      custodyIntentId: intent.intentId,
      blindContentId: intent.blindContentId,
      ciphertextRoot: intent.ciphertextRoot
    }
    if (Number.isFinite(intent.contentVersion)) body.contentVersion = intent.contentVersion
    if (Number.isFinite(intent.retainUntil)) body.retainUntil = intent.retainUntil
    return this._postSeed(relayUrl, body, opts)
  }

  async _postSeed (relayUrl, body, opts = {}) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const headers = { 'Content-Type': 'application/json' }
    // /seed (core relay-node/api.js) requires Bearer auth — same scheme as the
    // custody POST endpoints (_postCustody). The X-API-Key header is ignored.
    if (opts.apiKey) headers.Authorization = 'Bearer ' + opts.apiKey
    const res = await _fetchJson(base + '/seed', {
      method: 'POST',
      headers,
      body: JSON.stringify(body || {})
    })
    if (!res.ok) {
      const err = new Error('seed endpoint failed: ' + (res.body?.error || res.status))
      err.status = res.status
      err.body = res.body
      throw err
    }
    return res.body
  }

  // ─── PVSS blind custody (dealer-side orchestration) ─────────────────
  //
  // The DX payoff: compose split (secret-sharing.js) + signed v2 intents/commits
  // (custody.js) + share-bundle replication + the existing custody control
  // channel into two calls. The relay never sees the secret, never runs split,
  // never reconstructs — it holds an opaque guardian-encrypted share it can only
  // publicly verify. Only `key`/`secretPoint` (dealer-private) are returned to
  // the caller and must never be published.
  //
  // Quorum model: `threshold` (t) is the PVSS RECONSTRUCTION threshold; custody
  // requires every assigned relay to hold + verify its share, so the intent's
  // `requiredReplicas` equals the relay/share count n (it is also the upper
  // bound on shareIndex and the commit quorum floor — see core
  // validateCustodyTransition). The secret later recovers from any t guardians.

  /**
   * Blind-custody a secret t-of-n across a relay quorum (PVSS over secp256k1).
   *
   * @param {object} params
   * @param {string} [params.secret] 64-hex scalar; random if omitted
   * @param {string[]} params.guardians recipient pubkey hexes (length n ≥ t);
   *   only holders of the matching secret keys can later decrypt a share
   * @param {number} params.threshold reconstruction threshold t (1 ≤ t ≤ n)
   * @param {Array<{url:string,pubkey:string}>} params.relays custodying relays
   *   (length n); relays[i] is assigned shareIndex i+1
   * @param {string} params.appKey 64-hex content drive key this custody binds to
   * @param {object} params.opts blindContentId, ciphertextRoot, contentVersion,
   *   deadlineMs, retainMs, apiKey, maxStorage, pollIntervalMs, pollTimeoutMs,
   *   timestamp. maxStorage is a required positive safe-integer byte bound.
   * @returns {Promise<{intentId:string, commitmentRoot:string,
   *   shareBundleKey:string, key:string, secretPoint:string, intent:object,
   *   commit:object, receipts:object[]}>}
   */
  async splitForCustody ({ secret, guardians, threshold, relays, appKey, opts = {} } = {}) {
    if (!this.keyPair || !this.keyPair.secretKey) {
      throw new Error('splitForCustody: client keyPair required (call start() first)')
    }
    if (!Array.isArray(guardians) || guardians.length < 1) {
      throw new Error('splitForCustody: guardians[] required')
    }
    if (!Number.isInteger(threshold) || threshold < 1) {
      throw new Error('splitForCustody: threshold must be a positive integer')
    }
    if (!Array.isArray(relays) || relays.length !== guardians.length) {
      throw new Error('splitForCustody: relays[] length must equal guardians[] length (one share per relay)')
    }
    if (threshold > relays.length) {
      throw new Error('splitForCustody: threshold exceeds relay/share count')
    }
    const appKeyHex = typeof appKey === 'string' ? appKey : (appKey ? b4a.toString(appKey, 'hex') : null)
    if (!appKeyHex || !/^[0-9a-f]{64}$/i.test(appKeyHex)) {
      throw new Error('splitForCustody: appKey must be a 64-hex drive key')
    }
    if (!Number.isSafeInteger(opts.maxStorage) || opts.maxStorage <= 0) {
      throw new Error('splitForCustody: opts.maxStorage must be a positive safe integer')
    }
    const maxStorage = opts.maxStorage

    // 1. Split the secret to the guardian recipient pubkeys.
    const res = await _pvssSplit({ threshold, shareholders: guardians, secret })

    // 2. Publish the PUBLIC share bundle over the replication data plane (a
    //    sibling hypercore the relays replicate) — no HTTP, no 0.7.2 dependency,
    //    no seed-request wire collision. Public material only; blind preserved.
    const shareBundleKey = await this._writeShareBundle(res.public)

    // 3. Author + sign the v2 custody intent (self-contained custody.js).
    const now = Number.isFinite(opts.timestamp) ? opts.timestamp : Date.now()
    const shareAssignments = relays.map((r, i) => {
      const relayPubkey = typeof r.pubkey === 'string' ? r.pubkey : (r.pubkey ? b4a.toString(r.pubkey, 'hex') : null)
      if (!relayPubkey) throw new Error('splitForCustody: relays[' + i + '].pubkey required')
      return { relayPubkey, shareIndex: i + 1 }
    })
    const intent = _createCustodyIntent({
      version: 2,
      blindContentId: opts.blindContentId || _custodyHashHex('hiverelay-blind:' + appKeyHex),
      ciphertextRoot: opts.ciphertextRoot || _custodyHashHex('hiverelay-cipher:' + appKeyHex),
      contentVersion: Number.isFinite(opts.contentVersion) ? opts.contentVersion : 1,
      addressKey: appKeyHex,
      requiredReplicas: relays.length,
      deadline: now + (Number.isFinite(opts.deadlineMs) ? opts.deadlineMs : 10 * 60 * 1000),
      retainUntil: now + (Number.isFinite(opts.retainMs) ? opts.retainMs : 30 * 24 * 60 * 60 * 1000),
      shareScheme: res.public.scheme,
      shareThreshold: threshold,
      commitmentRoot: res.public.commitmentRoot,
      shareBundleKey,
      shareAssignments
    }, this.keyPair, { timestamp: now })

    // 4. Hand the signed intent to each relay. SD3: the intent/commit CONTROL
    //    plane stays on the existing (tiny, publisher-authed) custody channel;
    //    only the bulky share DATA moved to P2P.
    for (const r of relays) {
      await this.publishCustodyIntent(r.url, intent, { apiKey: opts.apiKey })
    }

    // 4.5 Trigger each relay to SEED the custody addressKey under the intent it
    //     was just handed. This is the load-bearing step: a relay only verifies
    //     its assigned PVSS share + anchors a receipt from inside seedApp
    //     (core app-lifecycle.js → _recordCustodyReceipt). The intent/commit
    //     control channel alone never produces a receipt — without this seed,
    //     _awaitVerifiedReceipts below polls a quorum that never forms and every
    //     split times out with CUSTODY_QUORUM_TIMEOUT. /seed is authenticated,
    //     so opts.apiKey (per-relay Bearer) must be supplied. Per-relay failures
    //     are non-fatal: a relay that rejects the seed simply won't anchor, and
    //     the quorum poll decides overall success vs. timeout.
    for (const r of relays) {
      try {
        await this._seedForCustody(r.url, intent, { apiKey: opts.apiKey, maxStorage })
      } catch (err) {
        this.emit('custody-seed-error', {
          relay: r.url,
          intentId: intent.intentId,
          error: (err && err.message) || String(err)
        })
      }
    }

    // 5. Poll until every relay returns a share-VERIFIED, anchored receipt.
    const receipts = await this._awaitVerifiedReceipts(relays, intent.intentId, relays.length, opts)

    // 6. Commit the quorum (publisher-signed; binds the chosen receipt set).
    const relayQuorum = receipts.map(rcpt => rcpt.relayPubkey).sort()
    const commit = _createCustodyCommit({
      intentId: intent.intentId,
      blindContentId: intent.blindContentId,
      ciphertextRoot: intent.ciphertextRoot,
      contentVersion: intent.contentVersion,
      relayQuorum,
      receiptRoot: _computeReceiptRoot(receipts)
    }, this.keyPair, { timestamp: Date.now() })
    for (const r of relays) {
      try { await this.publishCustodyCommit(r.url, intent.intentId, commit, { apiKey: opts.apiKey }) } catch (_) {}
    }

    return {
      intentId: intent.intentId,
      commitmentRoot: res.public.commitmentRoot,
      shareBundleKey,
      key: res.key,
      secretPoint: res.secretPoint,
      intent,
      commit,
      receipts
    }
  }

  /**
   * Recover the dealer key from a blind custody, client-side, using any t
   * guardian secret keys. Reads the public share bundle, decrypts each
   * guardian's own share (matched by recovering its recipient pubkey from the
   * key), and Lagrange-reconstructs. A forged or merely-encrypted share is
   * rejected by reconstruct()'s per-share DLEQ check.
   *
   * @param {object} params
   * @param {string} params.intentId custody intent id
   * @param {string[]} params.guardianSecretKeys ≥ t guardian secret-key hexes
   * @param {Array<{url:string}|string>} [params.relays] relays to resolve the
   *   signed intent's shareBundleKey/threshold from (if not passed explicitly)
   * @param {string} [params.shareBundleKey] 64-hex bundle key (skips relay query)
   * @param {number} [params.threshold] reconstruction threshold (else from intent/bundle)
   * @returns {Promise<{key:string, secretPoint:string, shares:number}>}
   */
  async reconstructFromCustody ({ intentId, guardianSecretKeys, relays, shareBundleKey, threshold } = {}) {
    if (!Array.isArray(guardianSecretKeys) || guardianSecretKeys.length < 1) {
      throw new Error('reconstructFromCustody: guardianSecretKeys[] required')
    }
    let bundleKey = shareBundleKey || null
    let t = Number.isInteger(threshold) ? threshold : null
    if (!bundleKey) {
      const urls = Array.isArray(relays)
        ? relays.map(r => (typeof r === 'string' ? r : (r && r.url))).filter(Boolean)
        : []
      for (const url of urls) {
        let status = null
        try { status = await this.getCustodyStatus(url, intentId) } catch (_) { status = null }
        if (status && status.intent && status.intent.shareBundleKey) {
          bundleKey = status.intent.shareBundleKey
          if (t == null && Number.isInteger(status.intent.shareThreshold)) t = status.intent.shareThreshold
          break
        }
      }
    }
    if (!bundleKey) {
      throw new Error('reconstructFromCustody: could not resolve shareBundleKey (pass it explicitly or provide relays)')
    }

    const bundle = await this._readShareBundle(bundleKey)
    if (!bundle || !Array.isArray(bundle.encryptedShares)) {
      throw new Error('reconstructFromCustody: share bundle unavailable')
    }
    if (t == null && Number.isInteger(bundle.threshold)) t = bundle.threshold

    // Each guardian decrypts ONLY the share encrypted to it: decryptShare
    // returns shareholder = x·G, which matches the bundle's signed `shareholder`
    // field iff this key is that share's intended recipient.
    const decrypted = []
    const usedIndex = new Set()
    for (const secretKey of guardianSecretKeys) {
      for (const encryptedShare of bundle.encryptedShares) {
        if (usedIndex.has(encryptedShare.index)) continue
        let dec = null
        try { dec = await _pvssDecryptShare({ encryptedShare, secretKey }) } catch (_) { dec = null }
        if (dec && dec.shareholder === encryptedShare.shareholder) {
          decrypted.push(dec)
          usedIndex.add(encryptedShare.index)
          break
        }
      }
    }
    if (t != null && decrypted.length < t) {
      throw new Error('reconstructFromCustody: only ' + decrypted.length + ' of ' + t + ' shares decrypted')
    }
    // reconstruct() re-verifies each share's decryption DLEQ — an encrypted
    // share (Y_i) substituted for a decrypted one (S_i) fails here.
    const out = await _pvssReconstruct({ shares: decrypted, threshold: t || undefined })
    return { key: out.key, secretPoint: out.secretPoint, shares: decrypted.length }
  }

  /**
   * Poll each relay's custody status until `requiredCount` distinct relays have
   * returned an anchored, share-verified receipt for the intent. Returns those
   * receipts (lowest shareIndex first). Throws CUSTODY_QUORUM_TIMEOUT on expiry.
   */
  async _awaitVerifiedReceipts (relays, intentId, requiredCount, opts = {}) {
    const pollIntervalMs = Number.isFinite(opts.pollIntervalMs) ? opts.pollIntervalMs : 1000
    const pollTimeoutMs = Number.isFinite(opts.pollTimeoutMs) ? opts.pollTimeoutMs : 60_000
    const deadline = Date.now() + pollTimeoutMs
    const urls = relays.map(r => (typeof r === 'string' ? r : (r && r.url))).filter(Boolean)
    for (;;) {
      const byRelay = new Map()
      for (const url of urls) {
        let status = null
        try { status = await this.getCustodyStatus(url, intentId) } catch (_) { status = null }
        if (status && Array.isArray(status.receipts)) {
          for (const rcpt of status.receipts) {
            if (rcpt && rcpt.shareVerified === true && rcpt.anchored === true) {
              byRelay.set(rcpt.relayPubkey, rcpt)
            }
          }
        }
      }
      const verified = [...byRelay.values()].sort((a, b) => (a.shareIndex || 0) - (b.shareIndex || 0))
      if (verified.length >= requiredCount) return verified.slice(0, requiredCount)
      if (Date.now() >= deadline) {
        const err = new Error('splitForCustody: timed out waiting for ' + requiredCount +
          ' verified receipts (got ' + verified.length + ')')
        err.code = 'CUSTODY_QUORUM_TIMEOUT'
        err.receipts = verified
        throw err
      }
      await new Promise(resolve => setTimeout(resolve, pollIntervalMs))
    }
  }

  /**
   * Write a PUBLIC PVSS share bundle to a fresh sibling hypercore and serve it
   * so custodying relays can replicate block 0. Returns the 64-hex core key
   * (named in the signed intent as shareBundleKey). No secret material.
   */
  _writeShareBundle (bundle) {
    return this._trackOperation(this._writeShareBundleOwned(bundle))
  }

  async _writeShareBundleOwned (bundle) {
    if (!this.store) throw new Error('_writeShareBundle: client store not ready (call start() first)')
    const name = 'share-bundle-' + Date.now() + '-' + randomNameSuffix()
    const core = this.store.get({ name })
    let discovery = null
    try {
      await this._awaitLifecycleOwnerOperation(
        'share-bundle-core-ready:' + name,
        core,
        () => core.ready(),
        this.connectionTimeout
      )
      await this._awaitLifecycleOwnerOperation(
        'share-bundle-core-append:' + name,
        core,
        () => core.append(b4a.from(JSON.stringify(bundle))),
        this.connectionTimeout
      )
      // Serve block 0. The exact core + discovery session are owned until
      // destroy(), so custody publication cannot leave a hidden Corestore
      // writer or DHT announcement behind.
      if (this.swarm) {
        discovery = this.swarm.join(core.discoveryKey, { server: true, client: false })
        if (discovery && typeof discovery.flushed === 'function') {
          await this._awaitLifecycleOwnerOperation(
            'share-bundle-discovery-flush:' + name,
            discovery,
            () => discovery.flushed(),
            this.connectionTimeout
          )
        }
      }
      const keyHex = b4a.toString(core.key, 'hex')
      this._shareBundleCores.set(keyHex, { core, discovery })
      return keyHex
    } catch (err) {
      const keyHex = core.key ? b4a.toString(core.key, 'hex') : ('write:' + name)
      await this._closeTransientShareBundle(keyHex, { core, discovery }, err)
      throw err
    }
  }

  /**
   * Replicate + read a PUBLIC share bundle by its hypercore key. If block 0 is
   * already local (the dealer's own write), returns it without joining a topic.
   * Best-effort + non-throwing: returns the parsed bundle or null.
   */
  _readShareBundle (shareBundleKey, opts = {}) {
    return this._trackOperation(this._readShareBundleOwned(shareBundleKey, opts))
  }

  async _readShareBundleOwned (shareBundleKey, opts = {}) {
    if (typeof shareBundleKey !== 'string' || !/^[0-9a-f]{64}$/i.test(shareBundleKey) || !this.store) return null
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 30_000
    let core = null
    let discovery = null
    let readError = null
    try {
      core = this.store.get({ key: b4a.from(shareBundleKey, 'hex') })
      await this._awaitLifecycleOwnerOperation(
        'share-bundle-read-ready:' + shareBundleKey,
        core,
        () => core.ready(),
        Math.min(timeoutMs, this.connectionTimeout)
      )
      if (core.length === 0 && this.swarm) {
        discovery = this.swarm.join(core.discoveryKey, { server: false, client: true })
        if (discovery && typeof discovery.flushed === 'function') {
          await this._awaitLifecycleOwnerOperation(
            'share-bundle-read-discovery-flush:' + shareBundleKey,
            discovery,
            () => discovery.flushed(),
            Math.min(timeoutMs, 5_000)
          )
        }
      }
      const block = await core.get(0, { timeout: timeoutMs })
      if (!block) return null
      const parsed = JSON.parse(b4a.toString(block))
      return parsed && typeof parsed === 'object' ? parsed : null
    } catch (err) {
      readError = err
      return null
    } finally {
      if (core || discovery) {
        await this._closeTransientShareBundle(
          'read:' + shareBundleKey + ':' + randomNameSuffix(),
          { core, discovery },
          readError
        )
      }
    }
  }

  async fetchSeedingManifest (relayUrl, pubkey) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('fetchSeedingManifest: relayUrl required')
    }
    if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new Error('fetchSeedingManifest: pubkey must be 64 hex chars')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const endpoint = base + '/api/authors/' + pubkey.toLowerCase() + '/seeding.json'
    const res = await _fetchJson(endpoint, { method: 'GET' })
    if (res.status === 404) return null
    if (!res.ok) {
      const err = new Error('fetchSeedingManifest failed: ' + (res.body?.error || res.status))
      err.status = res.status
      throw err
    }
    const check = verifySeedingManifest(res.body)
    if (!check.valid) {
      throw new Error('fetched manifest failed verification: ' + check.reason)
    }
    if (check.pubkey.toLowerCase() !== pubkey.toLowerCase()) {
      throw new Error('fetched manifest pubkey mismatch')
    }
    return res.body
  }

  /**
   * Fetch and verify a relay's signed, OS-grounded accounting receipt.
   *
   * The relay endpoint is management-authenticated because receipts expose
   * operator/storage counters. Verification is local: the receipt signature is
   * checked against its relayPubkey and callers may additionally pin
   * opts.expectedPubkey to reject a valid receipt from the wrong relay.
   *
   * @param {string} relayUrl
   * @param {object} [opts]
   * @param {string} [opts.apiKey]           management bearer token
   * @param {boolean} [opts.refresh=true]    set false to avoid a fresh disk scan
   * @param {string} [opts.expectedPubkey]   optional 64-hex relay pubkey pin
   * @returns {Promise<{ok: true, verified: true, receipt: object}>}
   */
  async fetchAccountingReceipt (relayUrl, opts = {}) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('fetchAccountingReceipt: relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    const endpoint = base + '/api/accounting/receipt' + (opts.refresh === false ? '?refresh=0' : '')
    const headers = { Accept: 'application/json' }
    if (opts.apiKey) headers.Authorization = 'Bearer ' + opts.apiKey

    const res = await _fetchJson(endpoint, { method: 'GET', headers })
    if (!res.ok) {
      const err = new Error('fetchAccountingReceipt failed: ' + (res.body?.error || res.status))
      err.status = res.status
      err.body = res.body
      throw err
    }
    if (!res.body || !res.body.receipt || typeof res.body.receipt !== 'object') {
      throw new Error('fetchAccountingReceipt: malformed response')
    }

    const check = verifyAccountingReceipt(res.body.receipt)
    if (!check.valid) {
      throw new Error('fetchAccountingReceipt: receipt verification failed: ' + check.reason)
    }

    if (opts.expectedPubkey &&
        check.receipt.relayPubkey.toLowerCase() !== String(opts.expectedPubkey).toLowerCase()) {
      throw new Error('fetchAccountingReceipt: pubkey mismatch (expected ' + opts.expectedPubkey + ', got ' + check.receipt.relayPubkey + ')')
    }

    return { ok: true, verified: true, receipt: check.receipt }
  }

  /**
   * Fetch a relay's capability document. Useful for relay-shopping:
   * pick relays by version, accept_mode, features without opening a
   * swarm connection.
   *
   * Signature verification (added in v0.6.0): if the doc is signed and
   * `opts.requireSignature` is true (or the doc is signed and we
   * choose to verify), the signature is validated against the pubkey
   * IN the doc (TOFU). A failed verification emits 'capability-verify-error'
   * and throws — the relay is shipping tampered metadata.
   *
   * @param {string} relayUrl
   * @param {object} [opts]
   * @param {boolean} [opts.requireSignature=false]   throw if doc is unsigned
   * @param {boolean} [opts.requireFreshCapabilityDoc=false] throw if signed attestedAt is stale or missing
   * @param {number}  [opts.maxAgeMs]                  freshness window for stale warnings/strict verification
   * @param {number}  [opts.maxFutureSkewMs]           allowed future clock skew for strict verification
   * @param {string}  [opts.expectedPubkey]           pin pubkey (out-of-band trust)
   * @returns {Promise<object>}
   */
  async fetchCapabilities (relayUrl, opts = {}) {
    if (typeof relayUrl !== 'string' || !relayUrl.length) {
      throw new Error('fetchCapabilities: relayUrl required')
    }
    const base = relayUrl.replace(/\/+$/, '')
    // Auto-populate expectedPubkey from the known-relays registry.
    // Caller-provided opts.expectedPubkey wins; the registry only
    // fills in when the caller didn't pin explicitly.
    if (!opts.expectedPubkey && this._knownRelays && this._knownRelays.has(base)) {
      opts = { ...opts, expectedPubkey: this._knownRelays.get(base) }
    }
    let doc
    const res = await _fetchJson(base + '/.well-known/hiverelay.json', { method: 'GET' })
    if (res.ok) {
      doc = res.body
    } else {
      // Try the API mirror in case a reverse proxy hides /.well-known.
      const fallback = await _fetchJson(base + '/api/capabilities', { method: 'GET' })
      if (!fallback.ok) throw new Error('fetchCapabilities failed: ' + (res.body?.error || res.status))
      doc = fallback.body
    }

    // Signature verification — opt-in via requireSignature for now,
    // but we ALWAYS check when a signature is present and emit an
    // event on mismatch. A future revision could elevate signature
    // failures to throw by default.
    const requireFreshCapabilityDoc = opts.requireFreshCapabilityDoc === true || opts.requireFresh === true
    if (doc && doc.signature) {
      const verifyOpts = {}
      if (requireFreshCapabilityDoc) {
        verifyOpts.requireFresh = true
        if (typeof opts.maxAgeMs === 'number') verifyOpts.maxAgeMs = opts.maxAgeMs
        if (typeof opts.maxFutureSkewMs === 'number') verifyOpts.maxFutureSkewMs = opts.maxFutureSkewMs
        if (typeof opts.now === 'number') verifyOpts.now = opts.now
      }
      const check = verifyCapabilityDoc(doc, verifyOpts)
      if (!check.valid) {
        this.emit('capability-verify-error', { url: relayUrl, reason: check.reason })
        throw new Error('fetchCapabilities: signature verification failed: ' + check.reason)
      }
    } else if (opts.requireSignature || requireFreshCapabilityDoc) {
      const reason = requireFreshCapabilityDoc
        ? 'requireFreshCapabilityDoc was set'
        : 'requireSignature was set'
      throw new Error('fetchCapabilities: doc is unsigned and ' + reason)
    }

    // Pinned-pubkey check (out-of-band trust): if the caller knows
    // which pubkey the relay should have, fail fast on mismatch.
    if (opts.expectedPubkey && doc.pubkey && doc.pubkey.toLowerCase() !== opts.expectedPubkey.toLowerCase()) {
      this.emit('capability-pubkey-mismatch', {
        url: relayUrl,
        expected: opts.expectedPubkey,
        actual: doc.pubkey
      })
      throw new Error('fetchCapabilities: pubkey mismatch (expected ' + opts.expectedPubkey + ', got ' + doc.pubkey + ')')
    }

    // Staleness check (closes capability-doc replay sub-attack):
    // If the doc has an attestedAt timestamp older than maxAgeMs,
    // emit 'capability-doc-stale' so the caller can decide. We don't
    // throw — operators may legitimately leave caches running, and
    // a stale doc is still a known-good doc, just out of date.
    const maxAge = typeof opts.maxAgeMs === 'number' ? opts.maxAgeMs : 24 * 60 * 60 * 1000
    if (typeof doc.attestedAt === 'number' && doc.attestedAt > 0) {
      const now = typeof opts.now === 'number' ? opts.now : Date.now()
      const ageMs = now - doc.attestedAt
      if (ageMs > maxAge) {
        this.emit('capability-doc-stale', {
          url: relayUrl,
          attestedAt: doc.attestedAt,
          ageMs,
          maxAgeMs: maxAge
        })
      }
    }
    return doc
  }

  // ─── Quorum + fork-detection (v0.6.0 security additions) ──────────
  //
  // Implements docs/THREAT-MODEL.md defenses #1 (replica diversity) and
  // #2 (fork detection). All methods below are additive — apps that
  // don't call them keep working unchanged. Apps that do gain
  // structurally smaller attack surfaces against eclipse, withholding,
  // and silent equivocation.

  /**
   * Refresh the local capability-doc cache for a list of relays. Honors
   * a TTL so successive calls within the cache window are cheap.
   *
   * @param {string[]} relayUrls
   * @param {object} [opts]
   * @param {boolean} [opts.force=false]  bypass TTL
   * @returns {Promise<object[]>}  array of RelayInfo records
   */
  async refreshCapabilityCache (relayUrls, opts = {}) {
    if (!Array.isArray(relayUrls)) throw new Error('refreshCapabilityCache: relayUrls must be an array')
    const now = Date.now()
    const force = !!opts.force

    const results = []
    for (const url of relayUrls) {
      const cached = this._capabilityCache.get(url)
      if (!force && cached && (now - cached.fetchedAt) < this._capabilityCacheTtl) {
        results.push({ url, ...cached.relayInfo })
        continue
      }
      try {
        const doc = await this.fetchCapabilities(url)
        const relayInfo = capabilityDocToRelayInfo(url, doc)
        this._capabilityCache.set(url, { relayInfo, fetchedAt: now })
        results.push({ url, ...relayInfo })
      } catch (err) {
        // Don't throw — partial success matters for quorum selection.
        // The unreachable relay simply doesn't appear in the candidate
        // pool until next refresh.
        this.emit('capability-fetch-error', { url, error: err })
      }
    }
    return results
  }

  /**
   * Select a quorum from the cached capability docs.
   *
   * @param {object} [opts] — same shape as quorum-selector.selectQuorum
   * @returns {Array}  selected RelayInfo records (with `.diversityWarning` if applicable)
   */
  selectQuorum (opts = {}) {
    const candidates = []
    for (const [url, entry] of this._capabilityCache) {
      candidates.push({ url, ...entry.relayInfo })
    }
    const merged = {
      foundationPubkeys: this._foundationPubkeys,
      ...opts
    }
    const selected = selectQuorum(candidates, merged)
    if (selected.diversityWarning) {
      this.emit('quorum-warning', selected.diversityWarning)
    }
    return selected
  }

  /**
   * Convenience helper — describe the current quorum (size, regions,
   * operators, warning). Useful for UIs that want to show "you're
   * reading from N relays across M regions."
   */
  describeQuorum (selected) {
    return describeQuorum(selected)
  }

  /**
   * Issue an HTTP query to every relay in a quorum, in parallel.
   * Returns ALL responses (including failures) so the caller can do
   * its own comparison. Used by queryQuorumWithComparison() — most
   * apps will want that helper instead.
   *
   * @param {string} relativePath  path like '/catalog.json' or '/api/info'
   * @param {Array}  quorum        result of selectQuorum()
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=10000]
   * @returns {Promise<Array<{relay: string, ok: boolean, body?: any, error?: string}>>}
   */
  async queryQuorum (relativePath, quorum, opts = {}) {
    if (typeof relativePath !== 'string' || !relativePath.startsWith('/')) {
      throw new Error('queryQuorum: relativePath must start with /')
    }
    if (!Array.isArray(quorum) || quorum.length === 0) {
      throw new Error('queryQuorum: quorum must be a non-empty array')
    }
    const timeoutMs = opts.timeoutMs || 10_000
    return Promise.all(quorum.map(async (relay) => {
      if (!relay || !relay.url) return { relay: relay?.pubkey || '?', ok: false, error: 'no relay URL in quorum entry' }
      const url = relay.url.replace(/\/+$/, '') + relativePath
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), timeoutMs)
        const res = await globalThis.fetch(url, { signal: controller.signal })
        clearTimeout(timer)
        const text = await res.text().catch(() => '')
        let body = null
        try { body = text ? JSON.parse(text) : null } catch (_) { /* leave null */ }
        return { relay: relay.pubkey || relay.url, ok: res.ok, status: res.status, body }
      } catch (err) {
        return { relay: relay.pubkey || relay.url, ok: false, error: err.message }
      }
    }))
  }

  /**
   * Query a quorum AND compare responses for divergence. If responses
   * disagree on a value the caller declares "should be invariant"
   * (via opts.compareFields), report the divergence to ForkDetector
   * and emit a warning event.
   *
   * Returns { responses, agreed, divergent } so callers can decide how
   * to handle disagreement (fall back to majority, refuse to act,
   * surface to user, etc.).
   *
   * @param {string} relativePath
   * @param {Array}  quorum
   * @param {object} [opts]
   * @param {string[]} [opts.compareFields=[]]  fields that must agree across responses
   * @param {string} [opts.driveKey]            if comparing a specific drive, the hex key (used in fork records)
   */
  async queryQuorumWithComparison (relativePath, quorum, opts = {}) {
    const responses = await this.queryQuorum(relativePath, quorum, opts)
    const compareFields = opts.compareFields || []
    const okResponses = responses.filter(r => r.ok && r.body)
    if (okResponses.length < 2 || compareFields.length === 0) {
      return { responses, agreed: okResponses, divergent: [] }
    }
    const reference = okResponses[0]
    const divergent = []
    for (let i = 1; i < okResponses.length; i++) {
      const cmp = okResponses[i]
      const diffFields = compareFields.filter(f => reference.body?.[f] !== cmp.body?.[f])
      if (diffFields.length > 0) {
        divergent.push({
          relayA: reference.relay,
          relayB: cmp.relay,
          fields: diffFields,
          valuesA: Object.fromEntries(diffFields.map(f => [f, reference.body[f]])),
          valuesB: Object.fromEntries(diffFields.map(f => [f, cmp.body[f]]))
        })
      }
    }
    if (divergent.length > 0) {
      this.emit('quorum-divergence', { path: relativePath, divergent })
      // Optional: record as fork evidence if the caller passed a driveKey
      // and the comparison divergence is at the drive level (length /
      // version differences are equivocation candidates).
      if (opts.driveKey && this.forkDetector) {
        for (const d of divergent) {
          // Best-effort: encode the divergent values as evidence
          // payloads. A future revision should pull the actual signed
          // hypercore blocks; for now this captures the metadata so
          // the operator has something to investigate.
          this.forkDetector.report({
            hypercoreKey: opts.driveKey.toLowerCase(),
            blockIndex: 0,
            evidenceA: { fromRelay: d.relayA, block: JSON.stringify(d.valuesA), signature: 'metadata-only-' + d.relayA },
            evidenceB: { fromRelay: d.relayB, block: JSON.stringify(d.valuesB), signature: 'metadata-only-' + d.relayB }
          })
        }
      }
    }
    return { responses, agreed: okResponses, divergent }
  }

  /**
   * Striped multi-relay read. Splits a drive file into contiguous byte
   * ranges and fetches each range from a DIFFERENT relay's HTTP gateway
   * (via Range requests), then concatenates in order. No single relay sees
   * the whole object or the full access pattern — the read-side analogue of
   * the threat model's "replica diversity": metadata visibility is spread
   * across mutually-distrusting operators instead of concentrated in one.
   *
   * This is purely client-side and additive — it uses the public gateway
   * Range support (RFC 9110) that every relay already serves; relays need no
   * changes and are unaware they're serving a stripe.
   *
   * INTEGRITY CAVEAT: stripes are reassembled by byte offset. getStriped does
   * NOT cryptographically verify that the relays served consistent bytes — the
   * HTTP gateway path carries no per-block Merkle proof, so a malicious relay
   * can corrupt its stripe. The returned `ok` flag confirms total LENGTH only,
   * not content integrity. Use for public/non-sensitive content, or verify the
   * result against a known drive hash. Each stripe IS checked to be the exact
   * length requested, so a relay that ignores Range (returns the full body) is
   * rejected and the range is retried on another relay.
   *
   * @param {string} driveKey  64-hex drive key
   * @param {string} path      file path within the drive (e.g. '/index.html')
   * @param {object} [opts]
   * @param {Array}  [opts.quorum]    [{url,pubkey}] relays to stripe across (default: selectQuorum())
   * @param {number} [opts.stripes]   number of ranges to split into (default: quorum length)
   * @param {number} [opts.timeoutMs] per-stripe timeout (default 15000)
   * @returns {Promise<{ ok, bytes, buffer, stripes, relaysUsed, striped }>}
   */
  async getStriped (driveKey, path, opts = {}) {
    if (typeof driveKey !== 'string' || !/^[0-9a-f]{64}$/i.test(driveKey)) {
      throw new Error('getStriped: driveKey must be 64 hex chars')
    }
    if (typeof path !== 'string' || !path.startsWith('/')) {
      throw new Error('getStriped: path must start with /')
    }
    const quorum = (Array.isArray(opts.quorum) && opts.quorum.length)
      ? opts.quorum
      : this.selectQuorum(opts)
    const relays = quorum.filter(r => r && r.url)
    if (relays.length === 0) throw new Error('getStriped: no relays with URLs available')
    const timeoutMs = opts.timeoutMs || 15_000
    const relPath = '/v1/hyper/' + driveKey.toLowerCase() + path

    const fetchRange = async (relay, start, end) => {
      const url = relay.url.replace(/\/+$/, '') + relPath
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const headers = (start === null) ? {} : { Range: `bytes=${start}-${end}` }
        const res = await globalThis.fetch(url, { signal: controller.signal, headers })
        if (!res.ok) throw new Error('status ' + res.status)
        const buf = b4a.from(new Uint8Array(await res.arrayBuffer()))
        const total = parseContentRangeTotal(res.headers && res.headers.get && res.headers.get('content-range'))
        return { buf, total }
      } finally {
        clearTimeout(timer)
      }
    }

    // Fetch a range, trying the preferred relay first then the others — so a
    // bad/slow relay can't sink the whole read. Reject a response that isn't
    // the exact requested length (a relay that ignored Range and returned the
    // full body would otherwise be mis-concatenated into corrupt output).
    const fetchStripe = async (start, end, preferredIdx) => {
      const want = end - start + 1
      let lastErr = null
      for (let k = 0; k < relays.length; k++) {
        const relay = relays[(preferredIdx + k) % relays.length]
        try {
          const r = await fetchRange(relay, start, end)
          if (r.buf.length !== want) {
            lastErr = new Error('range not honored by ' + (relay.pubkey || relay.url))
            continue
          }
          return { start, buf: r.buf, relay: relay.pubkey || relay.url }
        } catch (err) {
          lastErr = err
        }
      }
      throw new Error('getStriped: no relay served range ' + start + '-' + end + (lastErr ? ' (' + lastErr.message + ')' : ''))
    }

    // Probe total size via a 1-byte ranged request; try relays until one
    // reports a Content-Range total. If none support Range, fall back to a
    // single full GET (reusing the body we already pulled when possible).
    let totalBytes = null
    let probeFullBuf = null
    let probeRelay = relays[0]
    for (const relay of relays) {
      try {
        const r = await fetchRange(relay, 0, 0)
        if (Number.isFinite(r.total) && r.total > 0) { totalBytes = r.total; probeRelay = relay; break }
        if (!probeFullBuf) probeFullBuf = r.buf // server ignored Range → full body
      } catch (_) { /* try next relay */ }
    }
    if (totalBytes === null) {
      const buf = probeFullBuf || (await fetchRange(probeRelay, null, null)).buf
      return { ok: true, bytes: buf.length, buffer: buf, stripes: 1, relaysUsed: [probeRelay.pubkey || probeRelay.url], striped: false }
    }

    const stripeCount = Math.max(1, Math.min(opts.stripes || relays.length, relays.length, totalBytes))
    const size = Math.ceil(totalBytes / stripeCount)
    const plan = []
    for (let i = 0; i < stripeCount; i++) {
      const start = i * size
      if (start >= totalBytes) break
      const end = Math.min(start + size, totalBytes) - 1
      plan.push({ start, end, preferredIdx: i % relays.length })
    }

    const parts = await Promise.all(plan.map(p => fetchStripe(p.start, p.end, p.preferredIdx)))
    parts.sort((a, b) => a.start - b.start)
    const buffer = b4a.concat(parts.map(p => p.buf))
    return {
      ok: buffer.length === totalBytes,
      bytes: buffer.length,
      buffer,
      stripes: parts.length,
      relaysUsed: [...new Set(parts.map(p => p.relay))],
      striped: true
    }
  }

  /**
   * Pin a known relay's identity pubkey. Future fetchCapabilities()
   * calls against this URL will fail if the served capability doc's
   * pubkey doesn't match. Use for out-of-band trust (e.g. operator
   * shared their pubkey via QR code, federation entry, or printed
   * card).
   *
   * @param {string} url
   * @param {string} pubkey  hex pubkey (64 chars)
   */
  pinRelay (url, pubkey) {
    if (typeof url !== 'string' || !url.length) throw new Error('pinRelay: url required')
    if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new Error('pinRelay: pubkey must be 64 hex chars')
    }
    this._knownRelays.set(url.replace(/\/+$/, ''), pubkey.toLowerCase())
  }

  /**
   * Remove a relay from the pinned-pubkey registry. Subsequent
   * fetchCapabilities() calls revert to TOFU (trust whatever pubkey
   * the doc claims).
   *
   * @param {string} url
   */
  unpinRelay (url) {
    return this._knownRelays.delete(url.replace(/\/+$/, ''))
  }

  /**
   * Snapshot of currently-pinned relays.
   * @returns {Array<{url: string, pubkey: string}>}
   */
  pinnedRelays () {
    return [...this._knownRelays.entries()].map(([url, pubkey]) => ({ url, pubkey }))
  }

  /**
   * Publish a fork proof to a list of relay URLs. Auto-signs the proof
   * with this client's identity key as the observer attestation —
   * relays REQUIRE the signature (closes attack 8.2 from
   * SECURITY-STRATEGY.md).
   *
   * The proof is wrapped in a signed envelope:
   *   { version: 1, proof, observer: { pubkey, signature, attestedAt } }
   *
   * Best-effort: relays that 4xx/5xx are noted in the result but
   * don't abort the broadcast.
   *
   * @param {object} proof    { hypercoreKey, blockIndex, evidence: [a, b] }
   * @param {string[]} relayUrls
   * @returns {Promise<Array<{relay: string, ok: boolean, error?: string}>>}
   */
  async publishForkProof (proof, relayUrls) {
    if (!proof || typeof proof !== 'object') throw new Error('publishForkProof: proof required')
    if (!Array.isArray(relayUrls) || relayUrls.length === 0) {
      throw new Error('publishForkProof: relayUrls must be a non-empty array')
    }
    if (!this.keyPair || !this.keyPair.secretKey) {
      throw new Error('publishForkProof: client has no identity key (signed proofs required)')
    }

    // Adapt ForkDetector's list() output to the unsigned-proof shape
    // signForkProof expects, if the caller passed a record (which has
    // `evidence` as an array already). Otherwise assume already in the
    // right shape.
    const unsigned = {
      hypercoreKey: proof.hypercoreKey,
      blockIndex: typeof proof.blockIndex === 'number' ? proof.blockIndex : 0,
      evidence: Array.isArray(proof.evidence) ? proof.evidence : []
    }
    const signed = signForkProof(unsigned, this.keyPair)

    return Promise.all(relayUrls.map(async (url) => {
      const endpoint = url.replace(/\/+$/, '') + '/api/forks/proof'
      try {
        const res = await _fetchJson(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(signed)
        })
        return { relay: url, ok: res.ok, status: res.status }
      } catch (err) {
        return { relay: url, ok: false, error: err.message }
      }
    }))
  }

  /**
   * Returns true if the ForkDetector has an unresolved fork on record
   * for this drive key. Quarantined drives should not be opened or
   * trusted until the operator resolves the fork.
   *
   * @param {string|Buffer} driveKey
   * @returns {boolean}
   */
  isDriveQuarantined (driveKey) {
    if (!this.forkDetector) return false
    const hex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    return this.forkDetector.isQuarantined(hex)
  }

  // ─── Pairing-over-swarm (multi-device, no QR) ──────────────────────
  //
  // The friction point of exportIdentity/importIdentity is "now go copy
  // 200 bytes of base64 to the other device." createPairingCode +
  // claimPairingCode let users pair via a 6-digit code instead, with the
  // identity bundle moving over an end-to-end-encrypted Hyperswarm channel
  // derived from the hashed code. The code itself never traverses the wire
  // (HMAC challenge/response). See packages/client/pairing.js for protocol
  // details and security notes.

  /**
   * Generate a one-time numeric code that another device can use to claim
   * a copy of this device's publishing identity. Spins up a swarm join on
   * the derived topic and waits for a peer.
   *
   * @param {object} [opts]
   * @param {number} [opts.ttlMs=300000] - Code lifetime (default 5 min)
   * @param {string} [opts.code] - Use this code instead of generating one
   *   (testing). Must be 6 digits.
   * @returns {Promise<{code: string, expiresAt: number, topic: Buffer}>}
   */
  async createPairingCode (opts = {}) {
    const mgr = attachPairing(this)
    return mgr.createPairingCode(opts)
  }

  /**
   * Claim a pairing code generated by another device. On success, this
   * client's identity is replaced with the one received from the source
   * device (importIdentity is called).
   *
   * @param {string} code - 6-digit numeric pairing code
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=30000] - Give up after this long
   * @returns {Promise<{ok: boolean, identity?: {publicKey: string}, reason?: string}>}
   */
  async claimPairingCode (code, opts = {}) {
    const mgr = attachPairing(this)
    return mgr.claimPairingCode(code, opts)
  }

  // ─── Service RPC ──────────────────────────────────────────────────

  /**
   * Call a remote service on a relay node.
   *
   *   const result = await client.callService('identity', 'whoami')
   *   const drive = await client.callService('storage', 'drive-create', {}, { relay: pubkeyHex })
   */
  async callService (service, method, params = {}, opts = {}) {
    this._ensureStarted()

    const relayPubkey = opts.relay || this._selectBestRelay('service')
    if (!relayPubkey) throw new Error('NO_RELAY: no relay with service channel')

    const relay = this.relays.get(relayPubkey)
    if (!relay?.channels?.service) {
      throw new Error('NO_SERVICE_CHANNEL: relay ' + relayPubkey + ' has no service protocol')
    }

    const id = this._serviceRequestId++
    const timeout = opts.timeout || 30_000

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pendingServiceRequests.delete(id)
        reject(new Error('SERVICE_TIMEOUT'))
      }, timeout)

      this._pendingServiceRequests.set(id, { resolve, reject, timer })

      relay.channels.service.msg.send({
        type: 1,
        id,
        service,
        method,
        params
      })
    })
  }

  /**
   * Subscribe to a relay's live service events over the P2P service RPC — the
   * streaming counterpart to callService(). Topics follow the producer
   * convention `<service>/<event>` (e.g. arbitration/resolved, sla/created,
   * events/<relay-event>); a service emits via node.router.pubsub.publish().
   *
   *   const off = client.subscribeService('arbitration', 'resolved', (data) => {…})
   *   off() // unsubscribe
   *
   * Topics are matched EXACTLY (no normalization). Pass hex keys in lowercase —
   * e.g. a poker tableKey: `subscribeService('poker', tableKey.toLowerCase(), …)`
   * — since the relay canonicalizes and publishes to the lowercase form; an
   * upper/mixed-case key yields a silently dead subscription.
   *
   * One MSG_SUBSCRIBE is sent for the first local listener on a (relay, topic)
   * pair; MSG_UNSUBSCRIBE when the last one detaches. Returns an unsubscribe fn.
   */
  subscribeService (service, event, onEvent, opts = {}) {
    this._ensureStarted()
    if (typeof onEvent !== 'function') throw new Error('subscribeService: onEvent must be a function')
    const topic = `${service}/${event}`
    if (topic.length > 256) throw new Error('subscribeService: topic too long (max 256)')

    const relayPubkey = opts.relay || this._selectBestRelay('service')
    if (!relayPubkey) throw new Error('NO_RELAY: no relay with service channel')
    const relay = this.relays.get(relayPubkey)
    if (!relay?.channels?.service) {
      throw new Error('NO_SERVICE_CHANNEL: relay ' + relayPubkey + ' has no service protocol')
    }

    const key = relayPubkey + '|' + topic
    let set = this._serviceSubscriptions.get(key)
    const firstForTopic = !set
    if (!set) { set = new Set(); this._serviceSubscriptions.set(key, set) }
    set.add(onEvent)
    if (firstForTopic) {
      relay.channels.service.msg.send({ type: 4, topics: [topic] }) // MSG_SUBSCRIBE
    }

    let active = true
    return () => {
      if (!active) return
      active = false
      const s = this._serviceSubscriptions.get(key)
      if (!s) return
      s.delete(onEvent)
      if (s.size === 0) {
        this._serviceSubscriptions.delete(key)
        const r = this.relays.get(relayPubkey)
        if (r?.channels?.service) {
          r.channels.service.msg.send({ type: 5, topics: [topic] }) // MSG_UNSUBSCRIBE
        }
      }
    }
  }

  /**
   * Trustlessly verify a relay holds + serves a specific app (Hyperdrive).
   *
   * The trust comes from Hypercore itself: every block replicated here is
   * verified against the drive key's signed Merkle root, so a relay CANNOT
   * fake content it doesn't hold — a forged/substituted block fails (and trips
   * the fork/verification hooks). We open the drive, confirm the relay is a
   * live peer advertising the full length, and download BOTH cores (metadata
   * and blobs) to completion — proving the genuine, complete content is present
   * and served, with zero trust in the relay's self-reported catalog.
   *
   * Caveat: replication rides the shared swarm, so `contentVerified` proves the
   * content is genuine + served by the swarm, and `relayHasFullLength` is R's
   * own advertised state — this is NOT a per-block, R-attributable, third-party
   * -portable proof. For that, use the signed proof-of-retrievability challenge (Tier 2).
   *
   *   const v = await client.verifySeeded(driveKey, { relay: relayPubkeyHex })
   *   //   { complete: true, relayHasFullLength: true, contentVerified: true, … }
   */
  async verifySeeded (driveKey, opts = {}) {
    this._ensureStarted()
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const relayPubkey = opts.relay
    if (!relayPubkey) throw new Error('verifySeeded: opts.relay (relay pubkey hex) is required')
    if (!this.relays.has(relayPubkey)) throw new Error('NO_RELAY: not connected to relay ' + relayPubkey)

    const timeout = opts.timeout || 30_000
    const drive = await this.open(keyHex, { wait: true, timeout })
    await drive.ready()
    const metaCore = drive.core
    const metaLength = metaCore.length || 0

    // Download the FULL drive — meta + blobs. Hypercore verifies every block
    // against the drive key on arrival; a bad block throws / quarantines.
    // We do this BEFORE inspecting peers: the download forces the connection to
    // the relay to fully establish + replicate, so its peer entry + advertised
    // remoteLength are reliably populated afterwards (reading them first races).
    let contentVerified = false
    let blobsLength = 0
    try {
      if (metaLength > 0) await metaCore.download({ start: 0, end: metaLength }).done()
      const blobs = await drive.getBlobs()
      blobsLength = (blobs && blobs.core && blobs.core.length) || 0
      if (blobsLength > 0) await blobs.core.download({ start: 0, end: blobsLength }).done()
      contentVerified = true
    } catch (err) {
      this.emit('verify-seeded-error', { driveKey: keyHex, error: err })
    }

    // Now locate the relay among the drive's peers (attribution) + its
    // advertised length — reliable only after replication has happened.
    const relayBuf = b4a.from(relayPubkey, 'hex')
    const relayPeer = (metaCore.peers || []).find((p) => {
      const rk = p && (p.remotePublicKey || (p.stream && p.stream.remotePublicKey))
      return rk && b4a.equals(rk, relayBuf)
    }) || null
    const relayRemoteLength = relayPeer ? (relayPeer.remoteLength || 0) : 0

    return this._seededVerdict({
      driveKey: keyHex,
      relay: relayPubkey,
      metaLength,
      blobsLength,
      relayIsPeer: !!relayPeer,
      relayRemoteLength,
      contentVerified
    })
  }

  /** Pure verdict from a verifySeeded probe — separated so it's unit-testable. */
  _seededVerdict ({ driveKey, relay, metaLength, blobsLength, relayIsPeer, relayRemoteLength, contentVerified }) {
    const relayHasFullLength = !!relayIsPeer && metaLength > 0 && relayRemoteLength >= metaLength
    return {
      driveKey,
      relay,
      relayIsPeer: !!relayIsPeer,
      relayHasFullLength,
      contentVerified: !!contentVerified,
      complete: relayHasFullLength && !!contentVerified,
      metaLength,
      blobsLength,
      relayRemoteLength
    }
  }

  /**
   * Tier-2 proof-of-retrievability probe — confirm a relay can produce an app by
   * making it produce signed Hypercore Merkle proofs for randomly-sampled blocks
   * of the drive's metadata core, each verified against the drive key alone.
   *
   * Stronger than `verifySeeded` in one dimension: every proof is signed by the
   * relay over a fresh nonce, so a passing result is per-block, relay-attributable,
   * and non-replayable. (Caveat — like all challenge-response storage proofs, a
   * relay could fetch-on-demand rather than store; random sampling + the latency
   * bound make that expensive, not impossible.)
   *
   *   const r = await client.proveSeeded(driveKey, { relay: relayPubkeyHex, samples: 5 })
   *   // r.ok === true only if EVERY sampled proof verified at the current head
   */
  async proveSeeded (driveKey, opts = {}) {
    this._ensureStarted()
    const keyHex = typeof driveKey === 'string' ? driveKey : b4a.toString(driveKey, 'hex')
    const relayPubkey = opts.relay
    if (!relayPubkey) throw new Error('proveSeeded: opts.relay (relay pubkey hex) is required')
    if (!this.relays.has(relayPubkey)) throw new Error('NO_RELAY: not connected to relay ' + relayPubkey)
    const proofSignatureProfile = normalizeProofSignatureProfile(opts.proofSignatureProfile)
    const proofEndpoint = await this._resolveRetrievabilityProofEndpoint(relayPubkey, opts)
    const proofTransport = proofEndpoint ? 'http' : 'service'

    // Cap samples below the relay's default per-caller proof burst (32) so a
    // single honest audit never self-throttles. 16 random blocks is a strong
    // sample; for small drives _sampleIndices clamps to the head anyway.
    const samples = Math.max(1, Math.min(opts.samples || 3, 16))
    const timeout = opts.timeout || 30_000

    // Open + update so drive.core.length is the metadata head we pin proofs to.
    const drive = await this.open(keyHex, { wait: true, timeout })
    await drive.ready()
    const head = drive.core.length || 0
    if (head <= 0) {
      return {
        ok: false,
        proofKind: PROOF_KIND_RETRIEVABILITY,
        proofLimit: RETRIEVABILITY_PROOF_LIMITATION,
        proofTransport,
        driveKey: keyHex,
        relay: relayPubkey,
        head: 0,
        passed: 0,
        total: 0,
        samples: [],
        reason: 'EMPTY_DRIVE'
      }
    }

    // Isolated verifier sandbox: a SEPARATE corestore (never swarm-joined) so
    // feeding it the relay's proofs can't race the live replication of the open
    // drive's core (corestore sessions share the same inner core by key). One
    // key-only core validates every sample — the author-signed root anchors all
    // of them, so a forged proof can't poison later samples.
    const sandboxDir = join(portableTmpdir(), 'hiverelay-verify-' + keyHex.slice(0, 16) + '-' + (this._serviceRequestId++) + '-' + this.relays.size)
    const sandbox = new Corestore(sandboxDir)
    const verifierCore = sandbox.get({ key: b4a.from(keyHex, 'hex') })
    await verifierCore.ready()

    const results = []
    try {
      for (const index of this._sampleIndices(head, samples)) {
        const nonce = b4a.alloc(32)
        sodium.randombytes_buf(nonce)
        let verdict
        try {
          const params = { coreKey: keyHex, index, nonce: b4a.toString(nonce, 'hex') }
          if (proofSignatureProfile) params.signatureProfile = proofSignatureProfile
          const response = proofEndpoint
            ? await this._postRetrievabilityProof(proofEndpoint, params, timeout)
            : await this.callService(
              'storage-proof', 'prove',
              params,
              { relay: relayPubkey, timeout }
            )
          verdict = await verifyStorageProof({
            verifierCore,
            response,
            expect: { driveKey: keyHex, index, nonce, relayPubkey, minLength: head }
          })
        } catch (err) {
          verdict = { valid: false, reason: (proofEndpoint ? 'HTTP_FAILED:' : 'CALL_FAILED:') + (err.code || err.message) }
        }
        results.push({
          index,
          transport: proofTransport,
          valid: !!(verdict && verdict.valid),
          proofKind: (verdict && verdict.proofKind) || PROOF_KIND_RETRIEVABILITY,
          signatureProfile: verdict && verdict.signatureProfile,
          reason: verdict && verdict.reason
        })
      }
    } finally {
      try { await sandbox.close() } catch {}
      try { await rm(sandboxDir, { recursive: true, force: true }) } catch {}
    }

    const passed = results.filter((r) => r.valid).length
    return {
      ok: passed === results.length && results.length > 0,
      proofKind: PROOF_KIND_RETRIEVABILITY,
      proofLimit: RETRIEVABILITY_PROOF_LIMITATION,
      proofTransport,
      driveKey: keyHex,
      relay: relayPubkey,
      head,
      passed,
      total: results.length,
      samples: results
    }
  }

  async _resolveRetrievabilityProofEndpoint (relayPubkey, opts = {}) {
    const mode = opts.proofTransport || 'auto'
    if (mode !== 'auto' && mode !== 'http' && mode !== 'service') {
      throw new Error('proveSeeded: opts.proofTransport must be auto, http, or service')
    }
    if (mode === 'service') return null

    const relayUrl = normalizeRelayUrl(opts.relayUrl)
    const cached = this._cachedRetrievabilityProofEndpoint(relayPubkey)
    if (cached) return cached
    if (!relayUrl) {
      if (mode === 'http') {
        throw new Error('proveSeeded: opts.relayUrl or cached capabilities required for proofTransport=http')
      }
      return null
    }

    let doc = null
    try {
      doc = await this.fetchCapabilities(relayUrl, {
        expectedPubkey: relayPubkey,
        maxAgeMs: opts.capabilityMaxAgeMs
      })
    } catch (err) {
      if (mode === 'http') throw err
      this.emit('proof-http-capability-error', { relay: relayPubkey, url: relayUrl, error: err })
      return null
    }

    const relayInfo = capabilityDocToRelayInfo(relayUrl, doc)
    if (this._capabilityCache && typeof this._capabilityCache.set === 'function') {
      this._capabilityCache.set(relayUrl, { relayInfo, fetchedAt: Date.now() })
    }
    if (relayInfoSupportsRetrievabilityHttp(relayInfo)) return relayUrl
    if (mode === 'http') {
      throw new Error('proveSeeded: relay capabilities do not advertise ' + CORE_RETRIEVABILITY_HTTP_FEATURE)
    }
    return null
  }

  _cachedRetrievabilityProofEndpoint (relayPubkey) {
    const target = String(relayPubkey || '').toLowerCase()
    const cache = this._capabilityCache
    if (!cache || typeof cache[Symbol.iterator] !== 'function') return null
    for (const [url, entry] of cache) {
      const relayInfo = entry && entry.relayInfo
      if (!relayInfo || typeof relayInfo.pubkey !== 'string') continue
      if (relayInfo.pubkey.toLowerCase() !== target) continue
      if (relayInfoSupportsRetrievabilityHttp(relayInfo)) return normalizeRelayUrl(url)
    }
    return null
  }

  async _postRetrievabilityProof (relayUrl, params, timeout) {
    const endpoint = normalizeRelayUrl(relayUrl) + '/api/proof/retrievability'
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    try {
      const res = await _fetchJson(endpoint, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      })
      if (!res.ok) {
        const code = res.body && res.body.error ? res.body.error : 'status ' + res.status
        const err = new Error('HTTP_PROOF_' + res.status + ':' + code)
        err.status = res.status
        err.body = res.body
        throw err
      }
      if (!res.body || typeof res.body !== 'object') throw new Error('HTTP_PROOF_BAD_RESPONSE')
      return res.body
    } finally {
      clearTimeout(timer)
    }
  }

  /** Distinct random block indices in [0, head). */
  _sampleIndices (head, n) {
    const maxHead = Math.min(Math.floor(head), 0xffffffff)
    const count = Math.min(Math.floor(n), maxHead)
    const set = new Set()
    while (set.size < count) set.add(sodium.randombytes_uniform(maxHead))
    return [...set]
  }

  /** Drop all local subscription state for a relay (its channel closed). */
  _dropRelaySubscriptions (relayPubkey) {
    const prefix = relayPubkey + '|'
    for (const key of this._serviceSubscriptions.keys()) {
      if (key.startsWith(prefix)) this._serviceSubscriptions.delete(key)
    }
  }

  // ─── Internal ────────────────────────────────────────────────────

  _onConnection (conn, info) {
    const pubkeyHex = info.publicKey
      ? b4a.toString(info.publicKey, 'hex')
      : null

    if (!pubkeyHex) return

    const mux = Protomux.from(conn)
    const channels = {}

    try {
      const seedChannel = mux.createChannel({
        protocol: SEED_PROTOCOL_NAME,
        id: null,
        handshake: c.raw,
        onopen: () => {
          for (const entry of this.seedRequests.values()) {
            if (channels.seed) {
              channels.seed.requestMsg.send(entry.request)
            }
          }
        },
        onclose: () => { channels.seed = null }
      })

      const requestMsg = seedChannel.addMessage({
        encoding: seedRequestEncoding,
        onmessage: () => {}
      })

      const acceptMsg = seedChannel.addMessage({
        encoding: seedAcceptEncoding,
        onmessage: (msg) => this._onSeedAccept(pubkeyHex, msg)
      })

      const unseedMsg = seedChannel.addMessage({
        encoding: unseedRequestEncoding,
        onmessage: () => {} // Client doesn't handle incoming unseed requests
      })

      // 4th message — relay-side deny with a machine-readable reason.
      // Relays that predate it never send one; protomux drops unknown ids
      // on their side, so registration order stays compatible.
      const denyMsg = seedChannel.addMessage({
        encoding: seedDenyEncoding,
        onmessage: (msg) => this._onSeedDeny(pubkeyHex, msg)
      })

      seedChannel._hiverelay = { requestMsg, acceptMsg, unseedMsg, denyMsg }
      channels.seed = { channel: seedChannel, requestMsg, acceptMsg, unseedMsg, denyMsg }
      seedChannel.open(b4a.from(JSON.stringify({ major: 1, minor: 0 })))
    } catch (err) {
      this.emit('protocol-error', { relay: pubkeyHex, protocol: 'seed', error: err })
    }

    try {
      const circuitChannel = mux.createChannel({
        protocol: CIRCUIT_PROTOCOL_NAME,
        id: null,
        onopen: () => {},
        onclose: () => { channels.circuit = null }
      })

      const reserveMsg = circuitChannel.addMessage({
        encoding: relayReserveEncoding,
        onmessage: () => {}
      })

      const connectMsg = circuitChannel.addMessage({
        encoding: circuitConnectEncoding,
        onmessage: () => {}
      })

      const statusMsg = circuitChannel.addMessage({
        encoding: circuitStatusEncoding,
        onmessage: (msg) => {
          const relay = this.relays.get(pubkeyHex)
          if (relay) relay.lastSeen = Date.now()
          this.emit('_circuit-status-' + pubkeyHex, msg)
          this.emit('relay-status', { relay: pubkeyHex, ...msg })
        }
      })

      // v0.8.19: data-plane message. Both sides of a bridged circuit
      // exchange opaque bytes through this. Server validates ownership,
      // applies byte/bandwidth caps, then forwards.
      const dataMsg = circuitChannel.addMessage({
        encoding: circuitDataEncoding,
        onmessage: (msg) => {
          if (!msg || msg.error || !msg.circuitId || !msg.data) return
          const relay = this.relays.get(pubkeyHex)
          if (relay) relay.lastSeen = Date.now()
          this.emit('circuit-data', {
            relay: pubkeyHex,
            circuitId: b4a.toString(msg.circuitId, 'hex'),
            data: msg.data
          })
        }
      })

      // v0.8.19: server signals "circuit is bridged" with the remote
      // peer's pubkey. Carries the circuitId clients should use for
      // subsequent dataMsg sends + the identity to verify in their own
      // Noise handshake on top.
      const readyMsg = circuitChannel.addMessage({
        encoding: circuitReadyEncoding,
        onmessage: (msg) => {
          if (!msg || msg.error || !msg.circuitId || !msg.remotePubkey) return
          const circuitIdHex = b4a.toString(msg.circuitId, 'hex')
          const remoteHex = b4a.toString(msg.remotePubkey, 'hex')
          this.emit('circuit-ready', {
            relay: pubkeyHex,
            circuitId: circuitIdHex,
            remotePubkey: remoteHex
          })
        }
      })

      // v0.8.19: explicit close notification from the server side.
      const closeMsgClient = circuitChannel.addMessage({
        encoding: circuitCloseEncoding,
        onmessage: (msg) => {
          if (!msg || msg.error || !msg.circuitId) return
          const circuitIdHex = b4a.toString(msg.circuitId, 'hex')
          this.emit('circuit-closed', {
            relay: pubkeyHex,
            circuitId: circuitIdHex,
            reason: msg.reason
          })
        }
      })

      channels.circuit = { channel: circuitChannel, reserveMsg, connectMsg, statusMsg, dataMsg, readyMsg, closeMsg: closeMsgClient }
      circuitChannel.open()

      // Forward transport channel (hiverelay-forward): demand-dialled relay
      // hop. One forward per relay connection (v1). connectViaForward() drives
      // openMsg/dataMsg and wraps them in a Duplex.
      const forwardChannel = mux.createChannel({ protocol: FORWARD_PROTOCOL_NAME, id: null, onclose: () => { this.emit('_forward-closed-' + pubkeyHex, { reason: 0 }) } })
      const fStatusMsg = forwardChannel.addMessage({
        encoding: forwardStatusEncoding,
        onmessage: (msg) => this.emit('_forward-status-' + pubkeyHex, msg)
      })
      const fDataMsg = forwardChannel.addMessage({
        encoding: forwardDataEncoding,
        onmessage: (msg) => this.emit('_forward-data-' + pubkeyHex, msg)
      })
      const fCloseMsg = forwardChannel.addMessage({
        encoding: forwardCloseEncoding,
        onmessage: (msg) => this.emit('_forward-closed-' + pubkeyHex, msg)
      })
      const fOpenMsg = forwardChannel.addMessage({ encoding: forwardOpenEncoding })
      channels.forward = { channel: forwardChannel, openMsg: fOpenMsg, dataMsg: fDataMsg, statusMsg: fStatusMsg, closeMsg: fCloseMsg, busy: false }
      forwardChannel.open()
    } catch (err) {
      this.emit('protocol-error', { relay: pubkeyHex, protocol: 'circuit', error: err })
    }

    // ─── Service Protocol Channel ───
    try {
      const serviceChannel = mux.createChannel({
        protocol: SERVICES_PROTOCOL_NAME,
        id: b4a.from('services-v1'),
        onopen: () => {
          this.emit('service-channel-open', { relay: pubkeyHex })
        },
        onclose: () => { channels.service = null; this._dropRelaySubscriptions(pubkeyHex) }
      })

      const serviceMsg = serviceChannel.addMessage({
        encoding: serviceMessageEncoding,
        onmessage: (msg) => this._onServiceMessage(pubkeyHex, msg)
      })

      channels.service = { channel: serviceChannel, msg: serviceMsg }
      serviceChannel.open()
    } catch (err) {
      this.emit('protocol-error', { relay: pubkeyHex, protocol: 'service', error: err })
    }

    if (!channels.seed && !channels.circuit && !channels.service) return

    this.relays.set(pubkeyHex, {
      conn,
      info,
      channels,
      connectedAt: Date.now(),
      lastSeen: Date.now()
    })

    if (!this._relayScores.has(pubkeyHex)) {
      this._relayScores.set(pubkeyHex, {
        latency: 0,
        successes: 0,
        failures: 0,
        bytesServed: 0,
        connectedSince: Date.now()
      })
    }

    conn.on('close', () => {
      this.relays.delete(pubkeyHex)
      this.reservations.delete(pubkeyHex)
      const closeScores = this._relayScores.get(pubkeyHex)
      if (closeScores) closeScores.failures++
      this.emit('relay-disconnected', { pubkey: pubkeyHex })
      if (this.relays.size === 0 && this._started) {
        this._attemptReconnect()
      }
    })

    conn.on('error', () => {
      this.relays.delete(pubkeyHex)
      const errorScores = this._relayScores.get(pubkeyHex)
      if (errorScores) errorScores.failures++
    })

    this._resetReconnect()
    this.emit('relay-connected', { pubkey: pubkeyHex })
  }

  _startReconnectLoop () {
    this._reconnect.timer = setInterval(() => {
      if (this.relays.size === 0 && this.autoDiscover && this._started) {
        this._attemptReconnect()
      }
    }, 30_000)
    if (this._reconnect.timer.unref) this._reconnect.timer.unref()
  }

  _attemptReconnect () {
    if (!this.autoDiscover || !this._started || this.swarm.destroyed) return

    const { delay, attempt } = this._reconnect
    const nextAttempt = attempt + 1

    this.emit('reconnecting', { attempt: nextAttempt, delay })

    // Destroy old discovery handle to prevent leaked DHT queries
    if (this._discoveryTopic) {
      this._queueDiscoveryDestroy(this._discoveryTopic)
      this._discoveryTopic = null
    }

    this._discoveryTopic = this.swarm.join(RELAY_DISCOVERY_TOPIC, {
      server: false,
      client: true
    })

    const nextDelay = Math.min(delay * 2, 60_000)
    this._reconnect.delay = nextDelay
    this._reconnect.attempt = nextAttempt
  }

  _startRelayHealthChecks () {
    const HEALTH_CHECK_INTERVAL = 60_000
    const STALE_THRESHOLD = 3 * 60 * 1000

    this._relayHealthInterval = setInterval(() => {
      const now = Date.now()
      for (const [pubkey, relay] of this.relays) {
        if (now - relay.lastSeen > STALE_THRESHOLD) {
          this.relays.delete(pubkey)
          this.reservations.delete(pubkey)
          this.emit('relay-stale', { pubkey })
          try { relay.conn.destroy() } catch (_) {}
        }
      }
    }, HEALTH_CHECK_INTERVAL)
    if (this._relayHealthInterval.unref) this._relayHealthInterval.unref()
  }

  _resetReconnect () {
    const wasReconnecting = this._reconnect.attempt > 0
    this._reconnect.delay = 5000
    this._reconnect.attempt = 0
    if (wasReconnecting) {
      this.emit('reconnected')
    }
  }

  _onSeedAccept (relayPubkeyHex, msg) {
    if (!msg || msg.error) {
      const appKeyHex = msg && msg.appKey && msg.appKey.byteLength === 32 ? b4a.toString(msg.appKey, 'hex') : null
      this.emit('invalid-accept', { appKey: appKeyHex, reason: msg && msg.error ? msg.error : 'malformed seed accept' })
      return
    }

    const now = Date.now()
    const relay = this.relays.get(relayPubkeyHex)
    if (relay) relay.lastSeen = now

    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    const entry = this.seedRequests.get(appKeyHex)

    if (entry) {
      // Reject any seed-accept that lacks relay identity or signature
      if (!msg.relayPubkey || !msg.relaySignature) {
        this.emit('seed-unsigned-reject', { key: appKeyHex, msg })
        return
      }

      // Verify relay signature before accepting
      const payload = b4a.concat([msg.appKey, msg.relayPubkey, b4a.from(msg.region || '')])
      const valid = sodium.crypto_sign_verify_detached(msg.relaySignature, payload, msg.relayPubkey)
      if (!valid) {
        this.emit('invalid-accept', { appKey: appKeyHex, reason: 'bad relay signature' })
        return
      }

      entry.acceptances.push(msg)
    }

    const relayScores = this._relayScores.get(relayPubkeyHex)
    if (relayScores) {
      relayScores.successes++
      // Opportunistic latency: round-trip time from seed request to accept
      if (entry && entry.sentAt) {
        const rtt = now - entry.sentAt
        // Exponential moving average (α=0.3) to smooth out variance
        relayScores.latency = relayScores.latency > 0
          ? Math.round(relayScores.latency * 0.7 + rtt * 0.3)
          : rtt
      }
    }

    this.emit('seed-accepted', {
      appKey: appKeyHex,
      relay: b4a.toString(msg.relayPubkey, 'hex'),
      region: msg.region
    })
  }

  _onSeedDeny (relayPubkeyHex, msg) {
    if (!msg || msg.error) {
      const appKeyHex = msg && msg.appKey && msg.appKey.byteLength === 32 ? b4a.toString(msg.appKey, 'hex') : null
      this.emit('invalid-deny', { appKey: appKeyHex, reason: msg && msg.error ? msg.error : 'malformed seed deny' })
      return
    }

    const relay = this.relays.get(relayPubkeyHex)
    if (relay) relay.lastSeen = Date.now()

    const claimedRelayHex = b4a.toString(msg.relayPubkey, 'hex')
    // Anti-spoof: a relay may only deny on its own behalf. The noise
    // stream authenticates the peer, so the claimed pubkey must match the
    // channel it arrived on.
    if (claimedRelayHex !== relayPubkeyHex) {
      this.emit('invalid-deny', { appKey: b4a.toString(msg.appKey, 'hex'), reason: 'relayPubkey mismatch' })
      return
    }

    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    const denial = {
      relay: claimedRelayHex,
      reasonCode: msg.reasonCode,
      detail: msg.detail || '',
      // 'queued-for-review' means "stop waiting for an accept from me, but
      // an operator may approve later" — not a terminal refusal.
      terminal: msg.reasonCode !== 'queued-for-review'
    }

    const entry = this.seedRequests.get(appKeyHex)
    if (entry) {
      if (!Array.isArray(entry.denials)) entry.denials = []
      // One denial per relay — a re-broadcast retry can produce duplicates.
      if (!entry.denials.some(d => d.relay === claimedRelayHex)) {
        entry.denials.push(denial)
      }
    }

    this.emit('seed-denied', { appKey: appKeyHex, ...denial })
  }

  _catalogEntryKey (entry) {
    if (!entry || typeof entry !== 'object') return null
    const key = entry.appKey || entry.key || entry.driveKey || entry.id
    return typeof key === 'string' && key.length > 0 ? key : null
  }

  _applyAppCatalogDelta (currentApps, added, removed) {
    const next = new Map()

    for (const app of Array.isArray(currentApps) ? currentApps : []) {
      const key = this._catalogEntryKey(app)
      if (key) next.set(key, app)
    }

    for (const key of Array.isArray(removed) ? removed : []) {
      if (typeof key === 'string') next.delete(key)
    }

    for (const app of Array.isArray(added) ? added : []) {
      const key = this._catalogEntryKey(app)
      if (key) next.set(key, app)
    }

    return [...next.values()]
  }

  _onServiceMessage (relayPubkey, msg) {
    // Basic type validation on incoming messages
    if (!msg || typeof msg.type !== 'number') return
    // For response/error types, validate id is a number
    if ((msg.type === 2 || msg.type === 3) && typeof msg.id !== 'number') return

    const relay = this.relays.get(relayPubkey)
    if (relay) relay.lastSeen = Date.now()

    if (msg.type === 2) { // MSG_RESPONSE
      const pending = this._pendingServiceRequests.get(msg.id)
      if (pending) {
        clearTimeout(pending.timer)
        this._pendingServiceRequests.delete(msg.id)
        pending.resolve(msg.result)
      }
    } else if (msg.type === 3) { // MSG_ERROR
      const pending = this._pendingServiceRequests.get(msg.id)
      if (pending) {
        clearTimeout(pending.timer)
        this._pendingServiceRequests.delete(msg.id)
        pending.reject(new Error(msg.error))
      }
    } else if (msg.type === 0) { // MSG_CATALOG
      const relay3 = this.relays.get(relayPubkey)
      if (relay3) relay3.serviceCatalog = msg.services || []
      this.emit('service-catalog', { relay: relayPubkey, services: msg.services })
    } else if (msg.type === 7) { // MSG_APP_CATALOG
      const relay2 = this.relays.get(relayPubkey)
      if (relay2) relay2.seededApps = msg.apps || []
      this.emit('app-catalog', { relay: relayPubkey, apps: msg.apps || [] })
    } else if (msg.type === 6) { // MSG_EVENT (live service-event fan-out)
      if (typeof msg.topic !== 'string') return
      const set = this._serviceSubscriptions.get(relayPubkey + '|' + msg.topic)
      if (set) {
        for (const cb of set) {
          try { cb(msg.data, msg.topic, relayPubkey) } catch { /* a subscriber's error must not kill the message loop */ }
        }
      }
      this.emit('service-event', { relay: relayPubkey, topic: msg.topic, data: msg.data })
    } else if (msg.type === 8) { // MSG_APP_CATALOG_DELTA
      const relay2 = this.relays.get(relayPubkey)
      const added = Array.isArray(msg.added) ? msg.added : (Array.isArray(msg.apps) ? msg.apps : [])
      const removed = Array.isArray(msg.removed) ? msg.removed : []
      const apps = this._applyAppCatalogDelta(relay2 ? relay2.seededApps : [], added, removed)
      if (relay2) relay2.seededApps = apps
      this.emit('app-catalog-delta', { relay: relayPubkey, added, removed, apps })
      this.emit('app-catalog', { relay: relayPubkey, apps, added, removed, delta: true })
    }
  }

  _serializeForSigning (msg) {
    const parts = [msg.appKey]

    // Hash discoveryKeys array (must match server's _serializeForSigning)
    const discoveryKeysHash = b4a.alloc(32)
    if (msg.discoveryKeys && msg.discoveryKeys.length > 0) {
      const dkConcat = b4a.concat(msg.discoveryKeys)
      sodium.crypto_generichash(discoveryKeysHash, dkConcat)
    }
    parts.push(discoveryKeysHash)

    // v2 signing layout — matches server SeedProtocol._serializeForSigning.
    // Bytes 0..27 are stable with v1; bytes 28..35 carry unseedFreezeMs;
    // bytes 36..39 reserved (zeros). Byte 1 is the revocable flag (was
    // reserved/zero in v1). Byte 2 is the durability tier.
    const meta = b4a.alloc(40)
    const view = new DataView(meta.buffer, meta.byteOffset)
    view.setUint8(0, msg.replicationFactor)
    view.setUint8(1, msg.revocable === false ? 0 : 1)
    view.setUint8(2, msg.durability || 0)
    view.setBigUint64(8, BigInt(msg.maxStorageBytes))
    view.setBigUint64(16, BigInt(msg.ttlSeconds))
    view.setUint32(24, msg.bountyRate || 0)
    view.setBigUint64(28, BigInt(msg.unseedFreezeMs || 0))
    parts.push(meta)
    return b4a.concat(parts)
  }

  _serializeForDomainSigning (msg) {
    return serializeSeedRequestForDomainSigning(msg)
  }

  _useSeedSignatureDomainV3 (opts) {
    return opts &&
      (opts.seedSignatureDomain === 'v3' ||
        opts.seedSignatureDomain === SEED_REQUEST_SIGNATURE_DOMAIN)
  }

  _selectBestRelay (requireProtocol = 'circuit') {
    let best = null
    let bestScore = -1

    for (const [pubkey, relay] of this.relays) {
      if (requireProtocol && !relay.channels[requireProtocol]) continue

      const scores = this._relayScores.get(pubkey) || { successes: 0, failures: 0, latency: 0, connectedSince: Date.now() }
      const total = scores.successes + scores.failures
      const reliability = total > 0 ? scores.successes / total : 0.5
      const uptimeHours = (Date.now() - scores.connectedSince) / 3600000
      const latencyPenalty = scores.latency > 0 ? 1000 / scores.latency : 1

      const composite = (reliability * 10) + (uptimeHours * 0.5) + latencyPenalty
      if (composite > bestScore) {
        bestScore = composite
        best = pubkey
      }
    }

    return best
  }

  getRelayScores () {
    const scores = []
    for (const [pubkey, data] of this._relayScores) {
      const total = data.successes + data.failures
      scores.push({
        relay: pubkey,
        reliability: total > 0 ? (data.successes / total * 100).toFixed(1) + '%' : 'N/A',
        successes: data.successes,
        failures: data.failures,
        uptimeHours: ((Date.now() - data.connectedSince) / 3600000).toFixed(1),
        latencyMs: data.latency
      })
    }
    return scores.sort((a, b) => parseFloat(b.reliability) - parseFloat(a.reliability))
  }

  _ensureStarted () {
    if (!this._started || this._stopping) throw new Error('Client not started — call await app.start() first')
    if (!this.store) throw new Error('No store available — pass a storage path or { store } option')
  }

  // ─── Directory Reading (for publish('./my-app') sugar) ──────────

  async _readDirectory (dirPath, rootDir, opts = {}) {
    if (!rootDir) rootDir = resolve(dirPath)
    const maxFileSize = opts.maxFileSize || 100 * 1024 * 1024
    const files = []
    const entries = await readdir(dirPath, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name)
      // Skip symlinks entirely to avoid traversal attacks
      const fileStat = await lstat(fullPath)
      if (fileStat.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        // Skip node_modules, .git, hidden dirs
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name.startsWith('.')) continue
        const subFiles = await this._readDirectory(fullPath, rootDir, opts)
        files.push(...subFiles)
      } else if (entry.isFile()) {
        // Skip files larger than maxFileSize (default 100 MB)
        if (fileStat.size > maxFileSize) continue
        const relPath = '/' + relative(rootDir, fullPath)
        const content = await readFile(fullPath)
        files.push({ path: relPath, content })
      }
    }
    return files
  }

  // ─── App→Drive Mapping Persistence ──────────────────────────────

  async _loadAppDriveMapping (appId) {
    if (!this._storagePath) return null
    try {
      const mapPath = join(this._storagePath, 'app-drives.json')
      const data = JSON.parse(await readFile(mapPath, 'utf8'))
      return data[appId] || null
    } catch (_) {
      return null
    }
  }

  _saveAppDriveMapping (appId, keyHex, opts = {}) {
    const operation = this._appDriveMappingTail.catch(() => {}).then(() => {
      return this._saveAppDriveMappingOwned(appId, keyHex, opts)
    })
    this._appDriveMappingTail = operation.catch(() => {})
    return operation
  }

  async _saveAppDriveMappingOwned (appId, keyHex, opts = {}) {
    if (!this._storagePath) return
    const throwOnError = opts.throwOnError === true
    let tempPath = null
    try {
      await mkdir(this._storagePath, { recursive: true })
      const mapPath = join(this._storagePath, 'app-drives.json')
      let data = {}
      try { data = JSON.parse(await readFile(mapPath, 'utf8')) } catch (_) {}
      if (Object.prototype.hasOwnProperty.call(opts, 'expectedCurrentKey')) {
        const current = data[appId] || null
        if (current !== opts.expectedCurrentKey) return { changed: false, current }
      }
      if (keyHex) data[appId] = keyHex
      else delete data[appId]
      tempPath = mapPath + '.tmp-' + randomNameSuffix()
      await writeFile(tempPath, JSON.stringify(data, null, 2))
      await rename(tempPath, mapPath)
      tempPath = null
      return { changed: true, current: keyHex || null }
    } catch (err) {
      if (tempPath) {
        try { await rm(tempPath, { force: true }) } catch (_) {}
      }
      if (throwOnError) throw err
    }
  }

  /**
   * Shut down everything cleanly.
   */
  destroy () {
    if (this._destroying) return this._destroying
    const operation = this._destroy()
    const destroying = operation.finally(() => {
      if (this._destroying === destroying) this._destroying = null
    })
    this._destroying = destroying
    return destroying
  }

  async _destroy () {
    this._stopping = true
    if (this._lifecycleAbort) this._lifecycleAbort.abort()

    // Let a concurrent start reach its cancellation check before touching any
    // owner it created. Startup flush is bounded; registry failure teardown is
    // strict, so this cannot silently strand a partially-started provider.
    const starting = this._starting
    if (starting) {
      try {
        await this._awaitOwnerOperation('client-start', starting, () => starting)
      } catch (err) {
        if (err?.code === 'CLIENT_TEARDOWN_TIMEOUT') {
          const failure = new Error('client startup did not settle before teardown')
          failure.code = 'CLIENT_TEARDOWN_FAILED'
          failure.cause = err
          throw failure
        }
      }
    }

    // Clean up health check timer
    if (this._relayHealthInterval) {
      clearInterval(this._relayHealthInterval)
      this._relayHealthInterval = null
    }

    // Clean up reconnect timer
    if (this._reconnect.timer) {
      clearInterval(this._reconnect.timer)
      this._reconnect.timer = null
    }
    this._reconnect.delay = 5000
    this._reconnect.attempt = 0

    // Stop replication monitors
    if (this._replicationMonitors) {
      for (const handle of this._replicationMonitors.values()) handle.stop()
      this._replicationMonitors.clear()
    }

    // Cancel pending seed retry timers (entries remain persisted for next session)
    for (const timer of this._pendingSeedTimers.values()) {
      clearTimeout(timer)
    }
    this._pendingSeedTimers.clear()

    // open()/share-bundle reads may have created Corestore sessions which are
    // not in `drives` yet. Drain them before closing discovery, swarm, or store.
    if (this._operations.size > 0) await this._drainOperations()

    // Flush queue to disk before teardown
    try { await this._savePendingSeeds() } catch (_) {}

    // Persist any in-memory fork records before tearing down. Fork
    // evidence is too valuable to lose on shutdown — operators may
    // not see the alert until the next session.
    if (this.forkDetector) {
      try { await this.forkDetector.save() } catch (_) {}
      this.forkDetector.removeAllListeners()
      this.forkDetector = null
    }
    // Capability cache is an in-memory optimization; nothing to persist.
    this._capabilityCache.clear()

    // Remove swarm connection listener (important for shared swarms)
    if (this._connectionHandler && this.swarm) {
      this.swarm.removeListener('connection', this._connectionHandler)
      this._connectionHandler = null
    }

    // Stop epoch-discovery refresh before destroying the exact sessions.
    if (this._epochDiscoveryTimer) {
      clearInterval(this._epochDiscoveryTimer)
      this._epochDiscoveryTimer = null
    }

    // Clean up pending service requests
    for (const pending of this._pendingServiceRequests.values()) {
      clearTimeout(pending.timer)
      pending.reject(new Error('CLIENT_DESTROYED'))
    }
    this._pendingServiceRequests.clear()
    this._serviceSubscriptions.clear()

    let firstOwnershipError = null

    // Stop registry strictly. A rejected stop retains the object and prevents
    // owner teardown so a later destroy() can retry against a live Corestore.
    if (this._registry) {
      const registry = this._registry
      try {
        await this._awaitOwnerOperation('registry-stop', registry, () => registry.stop())
        if (this._registry === registry) this._registry = null
      } catch (err) {
        firstOwnershipError = err
      }
    }

    // Tear down any pending pair codes / listeners
    if (this._pairing) {
      const pairing = this._pairing
      try {
        await this._awaitOwnerOperation('pairing', pairing, () => pairing.destroy())
        if (this._pairing === pairing) this._pairing = null
      } catch (err) {
        if (!firstOwnershipError) firstOwnershipError = err
      }
    }

    // Stop and persist bootstrap cache
    if (this._bootstrapCache) {
      this._bootstrapCache.stop()
      try { await this._bootstrapCache.save() } catch (_) {}
      this._bootstrapCache = null
    }

    try { await this._destroyDiscoveryHandles() } catch (err) {
      if (!firstOwnershipError) firstOwnershipError = err
    }
    try { await this._destroyShareBundles() } catch (err) {
      if (!firstOwnershipError) firstOwnershipError = err
    }
    try { await this._destroyProvisionalPublishes() } catch (err) {
      if (!firstOwnershipError) firstOwnershipError = err
    }

    // Close all drives only after their exact DHT sessions settle.
    if (!firstOwnershipError) {
      for (const [keyHex] of [...this.drives]) {
        try {
          await this.closeDrive(keyHex)
        } catch (err) {
          if (!firstOwnershipError) firstOwnershipError = err
        }
      }
    }

    if (firstOwnershipError) {
      const failure = new Error('client lifecycle teardown did not settle')
      failure.code = 'CLIENT_TEARDOWN_FAILED'
      failure.cause = firstOwnershipError
      throw failure
    }

    this.relays.clear()
    this.seedRequests.clear()
    this.reservations.clear()

    // Only destroy things we created. Null exact owned instances after their
    // teardown settles so start() allocates fresh owners instead of reusing a
    // dead Hyperswarm/Corestore.
    if (this._ownsSwarm && this.swarm) {
      const swarm = this.swarm
      await this._awaitOwnerOperation('owned-swarm', swarm, () => swarm.destroy())
      if (this.swarm === swarm) this.swarm = null
    }
    if (this._ownsStore && this.store) {
      const store = this.store
      await this._awaitOwnerOperation('owned-store', store, () => store.close())
      if (this.store === store) this.store = null
    }
    if (this._ownsSwarm && !this._keyPairExplicit) this.keyPair = null
    this._lifecycleAbort = null

    this._started = false
    this._stopping = false
    this.emit('destroyed')
  }
}

function randomNameSuffix (bytes = 8) {
  const out = b4a.alloc(bytes)
  sodium.randombytes_buf(out)
  return b4a.toString(out, 'hex')
}

/**
 * Minimal JSON fetch helper used by the seeding-manifest and capabilities
 * methods. Uses globalThis.fetch (Node 18+, Bare via bare-fetch polyfill,
 * browsers natively). Returns {ok, status, body} rather than throwing on
 * non-2xx so callers can distinguish network errors from 404s.
 *
 * Request bodies are caller-provided strings; this helper doesn't do any
 * JSON-encoding (keep it transparent). Response body is always parsed as
 * JSON; empty / non-JSON responses yield body=null.
 */
async function _fetchJson (url, opts = {}) {
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('globalThis.fetch unavailable — upgrade to Node 18+ or install a fetch polyfill')
  }
  const response = await globalThis.fetch(url, opts)
  let body = null
  try {
    const text = await response.text()
    if (text) body = JSON.parse(text)
  } catch (_) {
    body = null
  }
  return { ok: response.ok, status: response.status, body }
}

function normalizeRelayUrl (url) {
  if (typeof url !== 'string' || !url.length) return null
  return url.replace(/\/+$/, '')
}

function relayInfoSupportsRetrievabilityHttp (relayInfo) {
  return !!(relayInfo &&
    Array.isArray(relayInfo.features) &&
    relayInfo.features.includes(CORE_RETRIEVABILITY_HTTP_FEATURE))
}

function normalizeProofSignatureProfile (profile) {
  if (profile == null || profile === '') return null
  if (
    profile === STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE ||
    profile === RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
  ) {
    return profile
  }
  throw new Error('proveSeeded: opts.proofSignatureProfile must be storage-proof-legacy-v1 or retrievability-proof-v1')
}

/**
 * Adapt a capability document (per docs/v0.5.1-CAPABILITIES.md) into
 * the RelayInfo shape that the QuorumSelector expects. The selector
 * only uses pubkey + region + operator + features; other fields are
 * ignored at selection time but preserved on the cache entry for any
 * caller that wants to inspect them.
 */
function capabilityDocToRelayInfo (url, doc) {
  if (!doc || typeof doc !== 'object') {
    return { url, pubkey: '', features: [] }
  }
  return {
    url,
    pubkey: typeof doc.pubkey === 'string' ? doc.pubkey : '',
    region: typeof doc.region === 'string' ? doc.region : null,
    // If the capability doc declares a separate operator pubkey (for
    // multi-relay operators), prefer it; otherwise the relay pubkey
    // is its own operator identity.
    operator: typeof doc.operator === 'string' ? doc.operator : doc.pubkey,
    features: Array.isArray(doc.features) ? doc.features : [],
    // Optional ranking signals — selectors can use these if present.
    score: typeof doc.score === 'number' ? doc.score : undefined,
    latencyMs: typeof doc.latencyMs === 'number' ? doc.latencyMs : undefined
  }
}
