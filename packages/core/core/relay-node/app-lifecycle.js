import Hyperdrive from 'hyperdrive'
import Hyperblobs from 'hyperblobs'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { mkdir, readFile, rm } from 'fs/promises'
import { join } from 'path'
import { updateWithTimeout, getDriveSize } from './cancellable-drive-update.js'
import { isAbortError } from './lifecycle-scope.js'
import { verifyShareBundleForRelay } from '../pvss.js'
import { positiveStorageBound } from '../../config/storage-cap.js'
import { STORAGE_SHARE_BUNDLE_MAX_BYTES } from '../../config/storage-admission-authority.js'
import {
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'

const TRACKED_STORAGE_MUTATION = Symbol('tracked-storage-mutation')
const TRACKED_STORAGE_REMOVAL = Symbol('tracked-storage-removal')
const STORAGE_RECOVERY_INGRESS = Symbol('storage-recovery-ingress')

async function boundedWait (operation, timeoutMs, label) {
  let timer = null
  try {
    return await Promise.race([
      Promise.resolve(operation),
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
          const err = new Error(label + ' timed out')
          err.code = 'STORAGE_OPERATION_TIMEOUT'
          reject(err)
        }, timeoutMs)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function stableCoreProofState (core, attempts = 4) {
  if (!core) throw new Error('proved core snapshot unavailable')
  for (let attempt = 0; attempt < attempts; attempt++) {
    const forkBefore = Number(core.fork ?? 0)
    const lengthBefore = Number(core.length)
    const byteLengthBefore = Number(core.byteLength)
    const lengthAfter = Number(core.length)
    const byteLengthAfter = Number(core.byteLength)
    const forkAfter = Number(core.fork ?? 0)
    if (Number.isSafeInteger(forkBefore) && forkBefore >= 0 && forkBefore === forkAfter &&
        Number.isSafeInteger(lengthBefore) && lengthBefore >= 0 && lengthBefore === lengthAfter &&
        Number.isSafeInteger(byteLengthBefore) && byteLengthBefore >= 0 && byteLengthBefore === byteLengthAfter) {
      return { fork: forkAfter, length: lengthAfter, byteLength: byteLengthAfter }
    }
  }
  throw new Error('proved core snapshot changed during validation')
}

function nonClosingCoreView (core) {
  return new Proxy(core, {
    get (target, property) {
      if (property === 'close') return async () => {}
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    }
  })
}

/**
 * AppLifecycle — owns seeding, unseeding, and manifest indexing for a RelayNode.
 *
 * Holds the seededApps Map (via node.appRegistry.apps) and the seed mutex. The
 * owning RelayNode delegates its public seedApp/unseedApp/verifyUnseedRequest/
 * broadcastUnseed methods here, and forwards emitted events so existing
 * listeners continue to work.
 */
export class AppLifecycle extends EventEmitter {
  constructor (node) {
    super()
    this.node = node
    this._seedTail = Promise.resolve()
    this._auxShareBundleResources = new Set()
    this._retiringDrives = new Map()
  }

  /**
   * The seededApps Map. Delegates to the AppRegistry so existing external
   * callers that reach into node.seededApps keep seeing the same instance.
   */
  get seededApps () {
    return this.node.appRegistry.apps
  }

  _joinDriveDiscovery (appKeyHex, discoveryKey, handles = null) {
    const handle = this.node.swarm.join(discoveryKey, { server: true, client: true })
    const entry = this.node.appRegistry.get(appKeyHex)
    const owned = entry?.discoveryHandles instanceof Set
      ? entry.discoveryHandles
      : (handles instanceof Set ? handles : null)
    if (owned) owned.add(handle)
    return handle
  }

  async _destroyDriveDiscoveries (entry) {
    const handles = entry?.discoveryHandles instanceof Set
      ? entry.discoveryHandles
      : new Set()
    let firstError = null
    for (const handle of [...handles]) {
      try {
        if (handle && typeof handle.destroy === 'function') await handle.destroy()
        handles.delete(handle)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  async _releaseAuxShareBundleResource (resource) {
    if (resource.onConnection && typeof this.node.swarm.removeListener === 'function') {
      this.node.swarm.removeListener('connection', resource.onConnection)
      resource.onConnection = null
    }
    if (resource.discovery) {
      try {
        if (typeof resource.discovery.destroy === 'function') await resource.discovery.destroy()
        resource.discovery = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    if (resource.tracker) {
      try {
        if (typeof resource.tracker.destroy === 'function') await Promise.resolve(resource.tracker.destroy())
        resource.tracker = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    if (resource.snapshotCore) {
      try {
        await resource.snapshotCore.close()
        resource.snapshotCore = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    if (resource.core) {
      try {
        await resource.core.close()
        resource.core = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    if (resource.auxStore) {
      try {
        await resource.auxStore.close()
        resource.auxStore = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    if (resource.auxPath) {
      try {
        await rm(resource.auxPath, { recursive: true, force: true })
        resource.auxPath = null
      } catch (err) {
        if (resource.readCause) err.readCause = resource.readCause
        throw err
      }
    }
    this._auxShareBundleResources.delete(resource)
  }

  async _drainAuxShareBundleResources (appKey = null) {
    let firstError = null
    for (const resource of [...this._auxShareBundleResources]) {
      if (appKey !== null && resource.appKey !== appKey) continue
      try { await this._releaseAuxShareBundleResource(resource) } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  _settleRetiringDrive (owner) {
    if (owner.settling) return owner.settling
    const operation = this._settleRetiringDriveOwned(owner)
    owner.settling = operation
    operation.then(
      () => { if (owner.settling === operation) owner.settling = null },
      () => { if (owner.settling === operation) owner.settling = null }
    )
    return operation
  }

  async _settleRetiringDriveOwned (owner) {
    const node = this.node
    const entry = owner.entry

    // This token is a completion barrier for the in-flight authoritative
    // footprint proof; it is not itself a destroyable resource. Await it
    // before touching the range/snapshot/drive graph it may still extend.
    const registration = entry.downloadRegistration
    if (registration?.settled) await registration.settled
    if (entry.downloadRegistration === registration) entry.downloadRegistration = null

    if (Array.isArray(entry.downloadRanges)) {
      const remaining = []
      let firstError = null
      for (const range of entry.downloadRanges) {
        try {
          if (range && typeof range.destroy === 'function') await Promise.resolve(range.destroy())
        } catch (err) {
          remaining.push(range)
          if (!firstError) firstError = err
        }
      }
      entry.downloadRanges = remaining.length > 0 ? remaining : null
      if (firstError) throw firstError
    }
    if (Array.isArray(entry.downloadSnapshotCores)) {
      const remaining = []
      let firstError = null
      for (const core of entry.downloadSnapshotCores) {
        try {
          if (core && typeof core.close === 'function') await core.close()
        } catch (err) {
          remaining.push(core)
          if (!firstError) firstError = err
        }
      }
      entry.downloadSnapshotCores = remaining.length > 0 ? remaining : null
      if (firstError) throw firstError
    }

    await this._drainAuxShareBundleResources(owner.appKey)
    await this._destroyDriveDiscoveries(entry)

    if (node.distributedDriveBridge && owner.bridgeRegistered !== false) {
      node.distributedDriveBridge.unregisterDrive(owner.appKey)
      owner.bridgeRegistered = false
    }
    if (entry.drive && typeof entry.drive.close === 'function') {
      await entry.drive.close()
      entry.drive = null
    }
    entry.discoveryKey = null
    entry.discoveryHandles = null

    if (owner.rejected === true) {
      if (owner.reservation && node.storageAdmission && !node.storageAdmission.rollback(owner.reservation)) {
        node.storageAdmission.failClosed('storage-drive-reservation-rollback-failed')
        throw new Error('storage drive reservation rollback failed')
      }
      this._retiringDrives.delete(owner.appKey)
      return
    }

    if (owner.forget) {
      node.appRegistry.delete(owner.appKey, { persist: false })
      try {
        if (typeof node.appRegistry.persistDelete === 'function') {
          await node.appRegistry.persistDelete(owner.appKey, {
            throwOnError: true,
            evictedAt: owner.evictedAt
          })
        } else {
          await node.appRegistry.flush({ throwOnError: true })
        }
        if (Number.isSafeInteger(owner.evictedAt) && owner.evictedAt > 0 &&
            typeof node.appRegistry.markEvicted === 'function') {
          await node.appRegistry.markEvicted(owner.appKey, owner.evictedAt)
        }
      } catch (err) {
        if (!node.appRegistry.has(owner.appKey)) {
          node.appRegistry.set(owner.appKey, entry, { persist: false })
        }
        throw err
      }
      if (node.storageAdmission && !node.storageAdmission.release(`drive:${owner.appKey}`)) {
        node.storageAdmission.failClosed('storage-drive-release-failed')
        throw new Error('storage drive commitment release failed')
      }
    }

    entry.retiring = false
    this._retiringDrives.delete(owner.appKey)
    this._emitSafely('unseeded', { appKey: owner.appKey, forgotten: owner.forget })
  }

  async drainRetiringDrives () {
    let firstError = null
    for (const owner of [...this._retiringDrives.values()]) {
      try { await this._settleRetiringDrive(owner) } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  /**
   * Open + hydrate the registry from disk and return the entries to
   * re-seed. This is the FAST half of restart recovery (open the bee,
   * read entries into the in-memory Map) and MUST be awaited before
   * start() returns: until the bee is open, appRegistry persistence
   * no-ops, so any app seeded in the gap between start() and reseed
   * would be set in memory but never written to disk. The slow half —
   * re-seeding each drive (swarm joins, replication) — is reseedDrives,
   * run fire-and-forget.
   *
   * @returns {Promise<Array>} entries to pass to reseedDrives
   */
  async loadRegistry () {
    const node = this.node
    const entries = await node.appRegistry.load()
    if (node.storageAdmission) {
      for (const entry of entries) {
        if (!entry?.appKey) continue
        node.storageAdmission.adoptRecovery(`drive:${entry.appKey}`, entry.maxStorage, { kind: 'drive' })
      }
    }
    if (!entries.length) {
      await this.migrateOldSeededApps()
      const migrated = typeof node.appRegistry.entries === 'function'
        ? [...node.appRegistry.entries()].map(([appKey, entry]) => ({ appKey, ...entry }))
        : []
      if (node.storageAdmission) node.storageAdmission.markRecoveryReady('drives')
      return migrated
    }
    if (node.storageAdmission) node.storageAdmission.markRecoveryReady('drives')
    return entries
  }

  /**
   * Re-seed drives for previously-persisted entries. Safe to run
   * fire-and-forget after start(); each seedApp cascades into
   * eagerReplicate (tracked by the LifecycleScope so stop() drains it).
   */
  async reseedDrives (entries) {
    if (!Array.isArray(entries) || !entries.length) return
    for (const entry of entries) {
      if (!entry.appKey) continue
      try {
        await this.seedApp(entry.appKey, {
          [STORAGE_RECOVERY_INGRESS]: true,
          appId: entry.appId || null,
          type: entry.type || 'app',
          parentKey: entry.parentKey || null,
          mountPath: entry.mountPath || null,
          version: entry.version || null,
          privacyTier: entry.privacyTier || null,
          blind: entry.blind || false,
          storageClass: entry.storageClass || null,
          availabilityClass: entry.availabilityClass || null,
          custodyIntentId: entry.custodyIntentId || null,
          blindContentId: entry.blindContentId || null,
          ciphertextRoot: entry.ciphertextRoot || null,
          contentVersion: entry.contentVersion,
          retainUntil: entry.retainUntil,
          shardIds: entry.shardIds || null,
          // v0.8.12: pass persisted maxStorage through to the reseed so
          // the size-check fires on startup too. Null for older entries
          // that predate cap persistence — the size-check is skipped in
          // that case (matches v0.8.11 reseed behavior).
          maxStorage: positiveStorageBound(entry.maxStorage) || undefined,
          // Preserve the paid-lease marker across restart so retainUntil stays
          // an enforced lease (sweep acts on it; eviction protects it).
          leaseManaged: entry.leaseManaged === true
        })
        this._emitSafely('reseeded', { appKey: entry.appKey })
      } catch (err) {
        this._emitSafely('reseed-error', { appKey: entry.appKey, error: err })
      }
    }
  }

  /**
   * Combined load + reseed. Retained for callers that want the whole
   * recovery in one await (e.g. the Bare relay entrypoint).
   */
  async reseedFromRegistry () {
    const entries = await this.loadRegistry()
    await this.reseedDrives(entries)
  }

  /**
   * One-time migration from old seeded-apps.json to unified app-registry.json.
   */
  async migrateOldSeededApps () {
    const node = this.node
    const oldPath = join(node.config.storage, 'seeded-apps.json')
    let raw
    try {
      raw = await readFile(oldPath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return
      throw err
    }
    let data
    try { data = JSON.parse(raw) } catch (err) {
      const failure = new Error('LEGACY_APP_INVENTORY_CORRUPT')
      failure.cause = err
      throw failure
    }
    if (!Array.isArray(data)) throw new Error('LEGACY_APP_INVENTORY_UNSUPPORTED')
    const entries = data
    if (!entries.length) return
    const seen = new Set()
    for (const entry of entries) {
      if (!entry || typeof entry.appKey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(entry.appKey)) {
        throw new Error('LEGACY_APP_INVENTORY_INVALID')
      }
      const canonicalKey = entry.appKey.toLowerCase()
      if (seen.has(canonicalKey)) throw new Error('LEGACY_APP_INVENTORY_DUPLICATE')
      seen.add(canonicalKey)
      entry.appKey = canonicalKey
    }

    for (const entry of entries) {
      const appKey = entry.appKey
      try {
        // Legacy JSON entries predate a durable bound. Register a placeholder
        // as unknown recovery so it can reopen serve-only without ever being
        // mistaken for a zero-byte fresh adoption.
        if (!node.appRegistry.has(appKey)) {
          node.appRegistry.set(appKey, { ...entry, discoveryKey: null, maxStorage: null }, { persist: false })
        }
        if (node.storageAdmission) {
          node.storageAdmission.adoptRecovery(`drive:${appKey}`, null, { kind: 'drive' })
        }
        await this.seedApp(appKey, {
          [STORAGE_RECOVERY_INGRESS]: true,
          appId: entry.appId || null,
          type: entry.type || 'app',
          parentKey: entry.parentKey || null,
          mountPath: entry.mountPath || null,
          version: entry.version || null,
          privacyTier: entry.privacyTier || null
        })
        this._emitSafely('reseeded', { appKey, source: 'migration' })
      } catch (err) {
        this._emitSafely('reseed-error', { appKey, error: err })
      }
    }
  }

  async seedApp (appKeyHex, opts = {}) {
    if (this.node?._storageIngressReady === false && opts[STORAGE_RECOVERY_INGRESS] !== true) {
      const err = new Error('storage recovery inventory is not ready for seed ingress')
      err.code = 'STORAGE_RECOVERY_INVENTORY_PENDING'
      throw err
    }
    const node = this.node
    if (!isValidHexKey(appKeyHex)) throw new Error('Invalid app key: must be 64 hex characters')
    appKeyHex = appKeyHex.toLowerCase()
    if (!opts[TRACKED_STORAGE_MUTATION] && node.storageAdmission?.runKeyMutation) {
      return node.storageAdmission.runKeyMutation(`drive:${appKeyHex}`, () => this.seedApp(appKeyHex, {
        ...opts,
        [TRACKED_STORAGE_MUTATION]: true
      }))
    }
    if (!node.seeder) throw new Error('Seeding not enabled')
    const retiringEntry = node.appRegistry.get(appKeyHex)
    if (this._retiringDrives.has(appKeyHex) || retiringEntry?.retiring === true) {
      const err = new Error('drive retirement is still pending')
      err.code = 'STORAGE_DRIVE_RETIREMENT_PENDING'
      throw err
    }

    const contentType = normalizeContentType(opts.type, 'app')
    const blind = opts.blind === true
    const storageClass = normalizeStorageClass(opts.storageClass, blind ? 'temporary' : 'persistent')
    const availabilityClass = normalizeAvailabilityClass(opts.availabilityClass, blind ? 'atomic-handoff' : 'always-on')
    const configuredRetainMs = Number(node.config.custody?.defaultRetainMs)
    const defaultTemporaryRetainMs = Number.isFinite(configuredRetainMs)
      ? Math.max(0, configuredRetainMs)
      : 30 * 24 * 60 * 60 * 1000
    const retainUntil = Number.isFinite(opts.retainUntil)
      ? Math.floor(opts.retainUntil)
      : (storageClass === 'temporary' || availabilityClass === 'atomic-handoff'
          ? Date.now() + defaultTemporaryRetainMs
          : null)
    const normalizedOpts = {
      ...opts,
      blind,
      storageClass,
      availabilityClass,
      retainUntil
    }
    const parentKey = typeof opts.parentKey === 'string' ? opts.parentKey.toLowerCase() : null
    const mountPath = typeof opts.mountPath === 'string' ? opts.mountPath.trim() : null
    if (parentKey && !isValidHexKey(parentKey, 64)) {
      throw new Error('Invalid parent key: must be 64 hex characters')
    }
    if (mountPath && !mountPath.startsWith('/')) {
      throw new Error('Invalid mountPath: must start with "/"')
    }
    if ((parentKey || mountPath) && contentType !== 'drive') {
      throw new Error('parentKey and mountPath are only valid for content type "drive"')
    }

    const privacyTier = normalizePrivacyTier(opts.privacyTier || opts.tier, 'public')
    if (node.policyGuard) {
      let policyOperation = 'replicate-user-data'
      if (blind === true) {
        policyOperation = 'replicate-encrypted-data'
      } else if (node.config.strictSeedingPrivacy === false && contentType === 'app') {
        policyOperation = 'serve-code'
      }
      const policy = node.policyGuard.check(appKeyHex, privacyTier, policyOperation)
      if (!policy.allowed) {
        throw new Error(`POLICY_VIOLATION: ${policy.reason}`)
      }
    }

    // Policy and request-shape rejection are pure and may run in serve-only
    // mode. Gate durable capability immediately afterwards, before mutation
    // lanes, Corestore sessions, or Hyperdrive adoption can begin.
    if (opts[STORAGE_RECOVERY_INGRESS] !== true &&
        typeof node.appRegistry?.assertDurableWritesAvailable === 'function') {
      node.appRegistry.assertDurableWritesAvailable()
    }

    // Already seeding this exact key — reconcile new opts against stored entry.
    //
    // Subtlety: AppRegistry.load() populates this.apps with placeholder
    // entries whose discoveryKey is null (set later during reseeding).
    // If we hit one of those, we MUST fall through to actually seed.
    // Treating a null-discoveryKey placeholder as "already seeded" was
    // the recurring null-pointer crash in v0.3.0–v0.8.2 — fixed here for
    // good.
    //
    // v0.8.12 (ask 6 in FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md):
    // before v0.8.12 we returned early without inspecting the new opts.
    // That swallowed re-pins that raised maxStorage — the canonical case
    // being a drive partial-pinned under v0.8.10's silent-cap-too-small
    // bug, then re-pinned with a larger cap after upgrading. We honor
    // those re-pins now via _reconcileSeedOptsOnRepin: cap-up + unanchored
    // retriggers replication; cap-down emits a warning; same/missing is
    // a no-op (matches prior behavior).
    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
        const dkHex = typeof existing.discoveryKey === 'string'
          ? existing.discoveryKey
          : b4a.toString(existing.discoveryKey, 'hex')
        const repin = await this._reconcileSeedOptsOnRepin(appKeyHex, existing, normalizedOpts)
        if (!repin.ok) {
          const err = new Error('Storage cap re-pin blocked: ' + repin.reason)
          err.code = 'STORAGE_CAP_REPIN_BLOCKED'
          err.repin = repin
          throw err
        }
        this._assertCommittedStorageAuthority(appKeyHex)
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, normalizedOpts)
        return { discoveryKey: dkHex, alreadySeeded: true, repin }
      }
      // else: placeholder entry from load() — fall through to seed properly.
    }

    // Serialize cross-key admission without polling. A queued caller can abort
    // or time out before it acquires the lane; its cancelled closure remains in
    // the tail only as a no-op barrier, so later seeds never overtake the live
    // owner or execute after their caller has already failed.
    return this._queueSeedAdmission(() =>
      this._seedAppInner(appKeyHex, normalizedOpts, contentType, parentKey, mountPath, privacyTier))
  }

  _queueSeedAdmission (run) {
    const previous = this._seedTail
    const scope = this.node?._scope || null
    const configured = Number(this.node?.config?.seedAdmissionTimeoutMs)
    const timeoutMs = Number.isSafeInteger(configured) && configured > 0 ? configured : 10_000
    let acquired = false
    let cancelled = null
    let timer = null
    let onAbort = null
    const cleanupWait = () => {
      if (timer) clearTimeout(timer)
      timer = null
      if (onAbort && scope?.signal) scope.signal.removeEventListener('abort', onAbort)
      onAbort = null
    }
    const waitingFailure = new Promise((_resolve, reject) => {
      timer = setTimeout(() => {
        if (acquired) return
        const err = new Error('seed admission wait timed out')
        err.code = 'STORAGE_SEED_ADMISSION_TIMEOUT'
        cancelled = err
        reject(err)
      }, timeoutMs)
      if (scope?.signal) {
        onAbort = () => {
          if (acquired) return
          const err = new Error('seed admission wait aborted')
          err.name = 'AbortError'
          err.code = 'ABORT_ERR'
          cancelled = err
          reject(err)
        }
        if (scope.signal.aborted) onAbort()
        else scope.signal.addEventListener('abort', onAbort, { once: true })
      }
    })
    const operation = previous.catch(() => {}).then(async () => {
      acquired = true
      cleanupWait()
      if (cancelled) throw cancelled
      if (scope?.aborted) {
        const err = new Error('seed admission aborted')
        err.name = 'AbortError'
        err.code = 'ABORT_ERR'
        throw err
      }
      return run()
    })
    this._seedTail = operation.catch(() => {})
    return Promise.race([operation, waitingFailure]).finally(() => {
      cleanupWait()
    })
  }

  _assertCommittedStorageAuthority (appKeyHex) {
    if (this.node.storageAdmission?.canAcknowledge(`drive:${appKeyHex}`)) return
    const err = new Error('seeded app storage authority is not durably committed')
    err.code = 'STORAGE_RECONCILIATION_REQUIRED'
    throw err
  }

  async _seedAppInner (appKeyHex, opts, contentType, parentKey, mountPath, privacyTier) {
    const node = this.node
    const recoveringEntry = this.seededApps.get(appKeyHex) || null
    const recoveringExisting = recoveringEntry !== null

    // Re-check after acquiring mutex — another call may have seeded it.
    // Same null-discoveryKey guard + v0.8.12 opts reconcile as the
    // pre-mutex check in seedApp().
    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
        const dkHex = typeof existing.discoveryKey === 'string'
          ? existing.discoveryKey
          : b4a.toString(existing.discoveryKey, 'hex')
        const repin = await this._reconcileSeedOptsOnRepin(appKeyHex, existing, opts)
        if (!repin.ok) {
          const err = new Error('Storage cap re-pin blocked: ' + repin.reason)
          err.code = 'STORAGE_CAP_REPIN_BLOCKED'
          err.repin = repin
          throw err
        }
        this._assertCommittedStorageAuthority(appKeyHex)
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, opts)
        return { discoveryKey: dkHex, alreadySeeded: true, repin }
      }
      // else: placeholder entry from load() — fall through.
    }

    // A registry placeholder is allowed to reopen at its already-persisted
    // commitment even while the relay is over cap. It is not permission for
    // an external request racing startup to enlarge (or manufacture) that
    // commitment. Preflight any cap difference before Hyperdrive/Corestore
    // adoption or registry mutation, and carry the old cap forward when the
    // request merely omits it.
    let recoveredCapPlan = null
    if (recoveringExisting) {
      recoveredCapPlan = this._preflightRecoveredEntryCap(appKeyHex, recoveringEntry, opts)
      if (!recoveredCapPlan.ok) {
        const err = new Error('Recovered-entry cap change blocked: ' + recoveredCapPlan.reason)
        err.code = 'STORAGE_CAP_REPIN_BLOCKED'
        err.repin = recoveredCapPlan
        throw err
      }
      opts = {
        ...opts,
        maxStorage: recoveredCapPlan.effectiveCap === null
          ? undefined
          : recoveredCapPlan.effectiveCap
      }
    }

    // Existing registry entries may be reopened while over cap so the node can
    // boot, serve, inspect and manually unseed them. Every genuinely NEW pin
    // must pass the logical-cap + physical-reserve gate. This never turns on
    // eviction; shedding remains an explicit operator policy.
    const storageKey = `drive:${appKeyHex}`
    let reservation = null
    if (!recoveringExisting || (recoveredCapPlan && recoveredCapPlan.changed)) {
      const requestedBytes = positiveStorageBound(opts.maxStorage)
      if (requestedBytes === null) {
        const err = new Error('Storage admission blocked: positive safe-integer maxStorage is required')
        err.code = 'STORAGE_BOUND_REQUIRED'
        throw err
      }
      reservation = node.storageAdmission
        ? node.storageAdmission.reserve(storageKey, requestedBytes, { kind: 'drive' })
        : { allowed: false, reason: 'storage-admission-unavailable' }
      if (!reservation.allowed) {
        const err = new Error('Storage admission blocked: ' + (reservation.reason || 'insufficient-storage'))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
    }

    const publisherPubkey = opts.publisherPubkey
      ? (typeof opts.publisherPubkey === 'string'
          ? opts.publisherPubkey
          : b4a.toString(opts.publisherPubkey, 'hex'))
      : null

    const appKey = b4a.from(appKeyHex, 'hex')
    // Use a per-app corestore session so drive.close() does NOT propagate to
    // the shared root store. A session shares the same key-addressed hypercore
    // objects (same _root.cores map, same key derivation for explicit keys) but
    // its _close() only tears down this session's refs — the root store stays
    // open for all other seeded drives. Without this, any unseed path (custody
    // expiry, eviction, manual unseed) would call corestore.close() on the root
    // store and wedge the entire relay until systemd restarted the process.
    // See: .planning/debug/CAPTURED-TRACE-2026-05-18.md (root cause confirmed).
    const drive = new Hyperdrive(node.store.session(), appKey)
    let durableAccepted = false
    const discoveryHandles = new Set()

    try {
      // 2026-05-24: hard timeout on drive.ready(). On a drive whose
      // underlying hypercore is in a bad state (corrupted index, hung
      // session, etc.), ready() can hang indefinitely — and because
      // reseedFromRegistry awaits seedApp sequentially, ONE such drive
      // blocks every subsequent entry from getting opened. Observed
      // live on milkyb-iad where reseed processed only 12 of 145
      // entries at startup, then hung forever on entry 13. The other
      // 132 entries' drives were never opened, so the periodic anchor
      // check + repair loop had nothing to iterate (skipped by the
      // `if (!entry.drive) continue` guards).
      //
      // 8 seconds is generous — drive.ready() on a healthy entry
      // resolves in milliseconds. If it doesn't, throw so seedApp's
      // outer try/catch in reseedFromRegistry catches it, emits a
      // reseed-error, and the next entry gets its turn.
      const READY_TIMEOUT_MS = 8000
      let readyTimer
      try {
        await Promise.race([
          drive.ready(),
          new Promise((_resolve, reject) => {
            readyTimer = setTimeout(
              () => reject(new Error('DRIVE_READY_TIMEOUT after ' + READY_TIMEOUT_MS + 'ms')),
              READY_TIMEOUT_MS
            )
            if (readyTimer.unref) readyTimer.unref()
          })
        ])
      } finally {
        if (readyTimer) clearTimeout(readyTimer)
      }

      const discoveryKey = drive.discoveryKey

      let authoritativeSizeBytes = null
      if (reservation) {
        const done = drive.findingPeers ? drive.findingPeers() : null
        try {
          this._joinDriveDiscovery(appKeyHex, discoveryKey, discoveryHandles)
          if (typeof node.swarm.flush === 'function') {
            const flush = boundedWait(
              node.swarm.flush(),
              node.config?.seedDiscoveryFlushTimeoutMs || 10_000,
              'drive discovery flush'
            )
            await (node._scope ? node._scope.race(flush) : flush)
          }
          const measured = await getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true })
          authoritativeSizeBytes = measured?.totalBytes
        } finally {
          if (done) done()
        }
        if (!Number.isSafeInteger(authoritativeSizeBytes) || authoritativeSizeBytes < 0) {
          const err = new Error('authoritative drive size unavailable')
          err.code = 'STORAGE_SIZE_PROOF_UNAVAILABLE'
          throw err
        }
        if (authoritativeSizeBytes > reservation.boundBytes) {
          const err = new Error('maxStorage is below the authoritative drive size')
          err.code = 'STORAGE_BOUND_BELOW_ACTUAL'
          err.actualBytes = authoritativeSizeBytes
          err.boundBytes = reservation.boundBytes
          throw err
        }
      }

      // Revocability commitments — recorded at seed time, derived from the
      // signed seed-request payload (committed by publisher signature, so
      // the publisher cannot later claim a different value).
      // - revocable: false  → publisher relinquishes unseed authority. Only
      //   the operator can take this content down; no signed unseed from
      //   the publisher will be honored against this entry.
      // - unseedFreezeMs: N → cooldown after seed before publisher unseed
      //   is honored. Acts as a safety valve / commit-then-think window.
      const revocable = opts.revocable !== false
      const unseedFreezeMs = Number.isFinite(opts.unseedFreezeMs) && opts.unseedFreezeMs > 0
        ? Math.floor(opts.unseedFreezeMs)
        : 0

      // Durability tier — 0 (standard) is the default and matches all
      // pre-v0.8 behavior. 1 (archive) opts the drive into AutoHeal: a
      // background scheduler maintains a diversity-enforced replica
      // fleet (≥7 replicas across ≥4 regions and ≥5 distinct operators)
      // by recruiting fresh replicas as old ones drop out.
      const durability = Number.isFinite(opts.durability) && opts.durability > 0
        ? Math.floor(opts.durability)
        : 0

      // maxStorage from the publisher's seed request — tracked on the
      // entry in v0.8.12 so a later re-pin can compare. The reconcile
      // path uses this to detect cap-raised re-pins (retrigger
      // replication) and cap-lowered re-pins (emit warning, ignore).
      const maxStorage = positiveStorageBound(opts.maxStorage)

      const previousRegistryEntry = node.appRegistry.get(appKeyHex) || null
      const readOnlyRecovery = recoveringExisting &&
        opts[STORAGE_RECOVERY_INGRESS] === true &&
        node.appRegistry.physicalReadOnly === true
      const nextRegistryEntry = {
        drive,
        discoveryKey,
        startedAt: Date.now(),
        bytesServed: 0,
        type: contentType,
        parentKey,
        mountPath,
        appId: opts.appId || null,
        version: opts.version || null,
        privacyTier,
        name: opts.name || opts.appId || null,
        description: opts.description || '',
        author: opts.author || null,
        categories: Array.isArray(opts.categories) ? opts.categories : null,
        blind: opts.blind || false,
        storageClass: opts.storageClass,
        availabilityClass: opts.availabilityClass,
        custodyIntentId: opts.custodyIntentId || null,
        blindContentId: opts.blindContentId || null,
        ciphertextRoot: opts.ciphertextRoot || null,
        contentVersion: Number.isFinite(opts.contentVersion) ? opts.contentVersion : null,
        retainUntil: Number.isFinite(opts.retainUntil) ? opts.retainUntil : null,
        shardIds: Array.isArray(opts.shardIds) ? opts.shardIds : null,
        publisherPubkey,
        revocable,
        unseedFreezeMs,
        durability,
        maxStorage,
        authoritativeSizeBytes,
        discoveryHandles,
        // Paid pin-lease marker (incentive/lease). When true, retainUntil is an
        // enforced lease deadline that the custody-expiry sweep acts on and
        // eviction must not shed early. Set by the lease gate on a verified seed.
        leaseManaged: opts.leaseManaged === true
      }
      if (readOnlyRecovery) {
        if (typeof node.appRegistry.attachRuntime !== 'function' ||
            node.appRegistry.attachRuntime(appKeyHex, {
              drive,
              discoveryKey,
              discoveryHandles,
              bytesServed: 0
            }) !== true) {
          throw new Error('APP_REGISTRY_RUNTIME_ATTACH_FAILED')
        }
      } else {
        node.appRegistry.set(appKeyHex, nextRegistryEntry, { persist: false })
      }

      const stagedRegistryEntry = node.appRegistry.get(appKeyHex)
      try {
        if (reservation && !node.storageAdmission.owns(reservation)) {
          throw new Error('storage reservation ownership lost before persistence')
        }
        if (!readOnlyRecovery) {
          if (typeof node.appRegistry.persistEntry === 'function') {
            await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
          } else {
            await node.appRegistry.flush({ throwOnError: true })
          }
        }
      } catch (err) {
        // Per-key CAS rollback: never restore a whole registry snapshot and
        // erase/resurrect unrelated concurrent mutations.
        if (!readOnlyRecovery) {
          try {
            if (node.appRegistry.get(appKeyHex) === stagedRegistryEntry) {
              node.appRegistry.delete(appKeyHex, { persist: false })
              if (previousRegistryEntry) {
                node.appRegistry.set(appKeyHex, previousRegistryEntry, { persist: false })
              }
            }
          } catch (rollbackErr) {
            this._emitSafely('registry-rollback-error', {
              appKey: appKeyHex,
              error: (rollbackErr && rollbackErr.message) || String(rollbackErr)
            })
          }
        }
        throw err
      }

      if (reservation && !node.storageAdmission.commit(reservation)) {
        node.storageAdmission.failClosed()
        const durableEntry = node.appRegistry.get(appKeyHex)
        if (durableEntry) durableEntry.storageReconciliationRequired = true
        const err = new Error('Storage reservation commit failed')
        err.code = 'STORAGE_RESERVATION_COMMIT_FAILED'
        err.durableAccepted = true
        throw err
      }
      durableAccepted = true

      if (recoveredCapPlan && recoveredCapPlan.changed) {
        this._emitSafely('seed-cap-raised', {
          appKey: appKeyHex,
          oldCap: recoveredCapPlan.oldCap,
          newCap: recoveredCapPlan.newCap,
          incrementalBytes: recoveredCapPlan.incrementalBytes,
          anchored: false,
          source: 'recovered-entry-repin',
          hint: 'Recovered entry cap raised after storage admission; normal recovery replication will use the new cap.'
        })
      }

      // Signal that we're looking for peers for this drive's cores only
      // after the accepted seed is durably recorded.
      const done = drive.findingPeers ? drive.findingPeers() : null
      try {
        this._joinDriveDiscovery(appKeyHex, discoveryKey, discoveryHandles)
        node.swarm.flush().then(() => { if (done) done() }).catch(() => { if (done) done() })
      } catch (_) {
        if (done) done()
      }

      // Eagerly replicate drive content. Extracted to a method in v0.8.12
      // so the alreadySeeded re-pin path can call it too — see
      // _reconcileSeedOptsOnRepin.
      //
      // Tracked in the LifecycleScope so stop() drains the loop before
      // tearing down the corestore (vector A1 in STALE-REF-INVENTORY.md).
      if (!readOnlyRecovery) {
        this._trackEagerReplicate(appKeyHex, drive, opts, { source: 'fresh-seed' })
      }

      // 2026-05-23: register persistent download ranges on the drive's
      // cores so they actively pull missing blocks from any peer that
      // has them — not only during the one-shot _eagerReplicate +
      // 60s-per-tick repairUnanchored windows. Without this, the
      // drive's cores have no registered "wants" between download
      // attempts; even when peers connect with missing blocks, no
      // requests fire. See bigdestiny2/p2p-hiverelay#23.
      //
      // Mirrors the pattern seeder.seedCore() uses for plain hypercores
      // (the seedingRegistry's local log core, hence the lone
      // hiverelay_cores_seeded=1 metric across an entire 112-app relay
      // before this fix). Now the drives' meta + blob cores get the
      // same persistent-want treatment.
      //
      // Best-effort + don't await: getBlobs() is lazy; if the blob core
      // isn't ready yet, the catch swallows + we skip blob registration
      // for this seed cycle. _eagerReplicate's drive.download('/') will
      // populate the blob core on next pass, then a subsequent
      // _registerPersistentDownloads call picks up the slack.
      if (!readOnlyRecovery) {
        this._registerPersistentDownloads(appKeyHex, drive).catch((err) => {
          this._emitSafely('persistent-download-error', {
            appKey: appKeyHex,
            error: err.message || String(err)
          })
        })
      }

      if (node.distributedDriveBridge) {
        try { node.distributedDriveBridge.registerDrive(appKeyHex, drive) } catch (_) {}
      }

      this._emitSafely('seeding', { appKey: appKeyHex, discoveryKey: b4a.toString(discoveryKey, 'hex') })
      return { discoveryKey: b4a.toString(discoveryKey, 'hex') }
    } catch (err) {
      if (durableAccepted || err.durableAccepted) {
        const durableEntry = node.appRegistry.get(appKeyHex)
        if (durableEntry) durableEntry.storageReconciliationRequired = true
        if (node.storageAdmission) node.storageAdmission.failClosed('storage-post-commit-reconciliation-required')
        err.durableAccepted = true
        this._emitSafely('storage-reconciliation-required', {
          appKey: appKeyHex,
          error: err && err.message ? err.message : String(err)
        })
        throw err
      }
      const owner = {
        appKey: appKeyHex,
        entry: { drive, discoveryKey: drive.discoveryKey, discoveryHandles },
        reservation,
        rejected: true,
        forget: false,
        bridgeRegistered: false
      }
      this._retiringDrives.set(appKeyHex, owner)
      try {
        await this._settleRetiringDrive(owner)
      } catch (teardownError) {
        const failure = new Error('rejected drive teardown did not settle')
        failure.code = 'STORAGE_DRIVE_TEARDOWN_UNSETTLED'
        failure.cause = err
        failure.teardownCause = teardownError
        throw failure
      }
      throw err
    }
  }

  /**
   * Fire-and-forget wrapper around _eagerReplicate that participates in
   * the LifecycleScope cancellation contract (see lifecycle-scope.js +
   * CANCELLATION-CONTRACT.md). Tracking the promise lets RelayNode.stop()
   * drain the loop before tearing down the corestore — closes vectors A1
   * (fresh-seed eager-replicate retry loop) and A4 (re-pin retrigger) in
   * STALE-REF-INVENTORY.md.
   *
   * Callers should NOT chain their own `.catch(() => {})` on the return —
   * this helper already swallows non-Abort errors via the `.catch()` inside.
   *
   * @returns {Promise} the tracked, error-swallowed promise (settles
   *   either way; the caller doesn't usually need to await it, but
   *   tests can).
   */
  _trackEagerReplicate (appKeyHex, drive, opts, meta = {}) {
    const node = this.node
    const scope = node && node._scope
    const promise = this._eagerReplicate(appKeyHex, drive, opts, meta)
      .catch((err) => {
        // AbortError is the normal exit path during stop() — swallow
        // silently. Anything else is unexpected; surface as a
        // recoverable reseed-error so observers see it.
        if (isAbortError(err)) return
        this._emitSafely('reseed-error', {
          appKey: appKeyHex,
          error: (err && err.message) || String(err),
          recoverable: true,
          source: meta.source || 'fresh-seed',
          hint: 'unexpected error in eagerReplicate; periodic repair monitor will keep retrying'
        })
      })
    if (scope) scope.tracked(promise)
    return promise
  }

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

  async _downloadProvedDriveRanges (drive, proof, opts = {}) {
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 120_000
    const signal = opts.signal || null
    const metaCore = proof?.metaCoreSnapshot
    const blobCore = proof?.blobCoreSnapshot
    if (!metaCore || !blobCore || !Number.isSafeInteger(proof?.metaLength) ||
        !Number.isSafeInteger(proof?.blobLength)) {
      throw new Error('authoritative drive range proof unavailable')
    }
    const trackers = []
    const add = (core, end) => {
      if (end <= 0) return
      const tracker = core.download({ start: 0, end })
      trackers.push(tracker)
    }
    add(metaCore, proof.metaLength)
    add(blobCore, proof.blobLength)
    let timer = null
    let abortHandler = null
    try {
      await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('download timeout')), timeoutMs)
        if (signal) {
          if (signal.aborted) {
            const err = new Error('Aborted')
            err.name = 'AbortError'
            reject(err)
            return
          }
          abortHandler = () => {
            const err = new Error('Aborted')
            err.name = 'AbortError'
            reject(err)
          }
          signal.addEventListener('abort', abortHandler)
        }
        Promise.all(trackers.map((tracker) => {
          if (typeof tracker.done === 'function') return tracker.done()
          if (typeof tracker.downloaded === 'function') return tracker.downloaded()
          throw new Error('drive range tracker unavailable')
        })).then(resolve, reject)
      })
    } finally {
      if (timer) clearTimeout(timer)
      if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
      for (const tracker of trackers) {
        try { tracker.destroy() } catch (_) {}
      }
    }
  }

  _validAnchoredProof (proof) {
    return Number.isSafeInteger(proof?.driveVersion) && proof.driveVersion > 0 &&
      Number.isSafeInteger(proof.metaLength) && proof.metaLength >= 0 &&
      Number.isSafeInteger(proof.blobLength) && proof.blobLength >= 0 &&
      Number.isSafeInteger(proof.totalBytes) && proof.totalBytes >= 0 &&
      Number.isSafeInteger(proof.metaFork) && proof.metaFork >= 0 &&
      Number.isSafeInteger(proof.blobFork) && proof.blobFork >= 0
  }

  async _closeDriveProof (proof) {
    for (const core of [proof?.metaCoreSnapshot, proof?.blobCoreSnapshot]) {
      if (core && typeof core.close === 'function') {
        try { await core.close() } catch (_) {}
      }
    }
    if (proof) {
      proof.metaCoreSnapshot = null
      proof.blobCoreSnapshot = null
    }
  }

  async _installPersistentDownloadProof (appKeyHex, drive, proof) {
    const node = this.node
    const entry = node.appRegistry && node.appRegistry.get(appKeyHex)
    if (!entry || entry.drive !== drive || !this._validAnchoredProof(proof) ||
        !proof.metaCoreSnapshot || !proof.blobCoreSnapshot) return false

    const metaState = stableCoreProofState(proof.metaCoreSnapshot)
    const blobState = stableCoreProofState(proof.blobCoreSnapshot)
    if (metaState.length !== proof.metaLength || metaState.fork !== proof.metaFork ||
        blobState.length !== proof.blobLength || blobState.fork !== proof.blobFork ||
        metaState.byteLength + blobState.byteLength !== proof.totalBytes) return false

    const nextRanges = []
    try {
      nextRanges.push(proof.metaCoreSnapshot.download({ start: 0, end: proof.metaLength }))
      nextRanges.push(proof.blobCoreSnapshot.download({ start: 0, end: proof.blobLength }))
    } catch (err) {
      for (const range of nextRanges) {
        try { range.destroy() } catch (_) {}
      }
      throw err
    }

    const previousRanges = Array.isArray(entry.downloadRanges) ? entry.downloadRanges : []
    const previousCores = Array.isArray(entry.downloadSnapshotCores) ? entry.downloadSnapshotCores : []
    entry.downloadRanges = nextRanges
    entry.downloadSnapshotCores = [proof.metaCoreSnapshot, proof.blobCoreSnapshot]
    proof.metaCoreSnapshot = null
    proof.blobCoreSnapshot = null

    for (const range of previousRanges) {
      try { if (range && typeof range.destroy === 'function') range.destroy() } catch (_) {}
    }
    for (const core of previousCores) {
      try { if (core && typeof core.close === 'function') await core.close() } catch (_) {}
    }
    return true
  }

  async _commitAnchoredProof (appKeyHex, drive, proof, tracked = false) {
    const node = this.node
    if (!tracked && node.storageAdmission?.runKeyMutation) {
      return node.storageAdmission.runKeyMutation(`drive:${appKeyHex}`, () =>
        this._commitAnchoredProof(appKeyHex, drive, proof, true))
    }
    if (!this._validAnchoredProof(proof)) return false
    if (!node.storageAdmission?.canAcknowledge(`drive:${appKeyHex}`)) return false
    const entry = node.appRegistry.get(appKeyHex)
    if (!entry || entry.drive !== drive || drive.closed || drive.closing) return false
    const previous = {
      anchored: entry.anchored,
      anchoredAt: entry.anchoredAt,
      anchoredLength: entry.anchoredLength,
      lastAnchorCheck: entry.lastAnchorCheck,
      storageProvedDriveVersion: entry.storageProvedDriveVersion,
      storageProvedMetaLength: entry.storageProvedMetaLength,
      storageProvedBlobLength: entry.storageProvedBlobLength,
      storageProvedTotalBytes: entry.storageProvedTotalBytes,
      storageProvedMetaFork: entry.storageProvedMetaFork,
      storageProvedBlobFork: entry.storageProvedBlobFork
    }
    const now = Date.now()
    node.appRegistry.update(appKeyHex, {
      anchored: true,
      anchoredAt: entry.anchoredAt || now,
      anchoredLength: proof.driveVersion,
      lastAnchorCheck: now,
      storageProvedDriveVersion: proof.driveVersion,
      storageProvedMetaLength: proof.metaLength,
      storageProvedBlobLength: proof.blobLength,
      storageProvedTotalBytes: proof.totalBytes,
      storageProvedMetaFork: proof.metaFork,
      storageProvedBlobFork: proof.blobFork
    }, { persist: false })
    try {
      if (typeof node.appRegistry.persistEntry === 'function') {
        await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
      } else {
        await node.appRegistry.flush({ throwOnError: true })
      }
    } catch (err) {
      if (node.appRegistry.get(appKeyHex) === entry) {
        node.appRegistry.update(appKeyHex, previous, { persist: false })
      }
      throw err
    }
    try {
      await this._installPersistentDownloadProof(appKeyHex, drive, proof)
    } catch (err) {
      this._emitSafely('persistent-download-error', {
        appKey: appKeyHex,
        error: err && err.message ? err.message : String(err)
      })
    }
    return true
  }

  /**
   * Eagerly replicate a drive with the v0.8.11 size-check. Called from:
   *   1. _seedAppInner — fresh seed, after the drive is created.
   *   2. _reconcileSeedOptsOnRepin — re-pin with raised maxStorage, drive
   *      already exists, we need to retrigger the size-check + download
   *      under the new cap.
   *
   * Was previously an inline closure inside _seedAppInner. Extracted in
   * v0.8.12 to support the re-pin path that swallows new opts on
   * alreadySeeded — see FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md ask (6).
   *
   * v0.8.13 (Reliability v2): every long await is wrapped in
   * `scope.race(...)` so a `stop()` call short-circuits the loop with an
   * AbortError, and the retry-delay sleep is `scope.sleep(...)` so it
   * exits promptly on abort instead of running the full RETRY_DELAYS
   * tail. The fire-and-forget wrapper (_trackEagerReplicate above)
   * registers this promise in node._scope so stop() waits for the bail
   * to complete before destroying the swarm / corestore. See
   * STALE-REF-INVENTORY.md vector A1.
   *
   * @param {string} appKeyHex
   * @param {Hyperdrive} drive
   * @param {object} opts - seed opts (maxStorage is the relevant field)
   * @param {{ source?: string }} [meta] - 'fresh-seed' | 'repin-cap-raised'
   */
  async _eagerReplicate (appKeyHex, drive, opts, meta = {}) {
    const node = this.node
    const scope = node && node._scope
    if (scope && scope.aborted) return
    if (!drive || drive.closed || drive.closing) return
    const discoveryKey = drive.discoveryKey
    const source = meta.source || 'fresh-seed'

    const MAX_RETRIES = 6
    // Tightened tail — 120s was wasteful when the repair monitor takes
    // over anyway. Total wall time: ~2 min instead of ~4 min.
    const RETRY_DELAYS = [5000, 10000, 15000, 30000, 30000, 30000]

    const aborted = () => scope ? scope.aborted : false
    const raceOr = (promise) => scope ? scope.race(promise) : promise

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      // Bail out if the drive was closed (e.g. by unseedApp) or the scope
      // was aborted (stop() / self-heal restart in progress).
      if (aborted() || drive.closed || drive.closing) return

      let pinnedProof = null
      try {
        this._joinDriveDiscovery(appKeyHex, discoveryKey)
        await raceOr(node.swarm.flush())

        if (aborted() || drive.closed || drive.closing) return

        // Cancellable update — on timeout, the helper detaches any
        // in-flight hypercore upgrade refs from the replicator's
        // activeRequests so they don't accumulate. Previously the
        // raw Promise.race left the upgrade ref pending, leading to
        // the "Cannot make sessions on a closing core" leak that
        // PR #14 papered over with 503 + Retry-After.
        await raceOr(updateWithTimeout(drive, { timeoutMs: 30_000 }))

        if (drive.version > 0 && !drive.closed && !drive.closing && !aborted()) {
          // ── Size-check the drive against the publisher's maxStorage ──
          //
          // See docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md for the case
          // study: relay accepts a seed request with maxStorage smaller
          // than the actual drive, replicates metadata fully, stalls
          // mid-blob, and never tells the publisher. Symptom on the
          // consumer side is an indistinguishable-from-network-down hang.
          //
          // Loud failure mode: emit a seed-aborted event AND unseed
          // locally if the actual size exceeds the cap the publisher
          // declared. Publisher sees the event (via SDK) at pin time
          // instead of discovering it via end-user reports.
          const liveBound = node.appRegistry && node.appRegistry.get(appKeyHex)?.maxStorage
          const cap = positiveStorageBound(liveBound ?? opts.maxStorage)
          // Legacy unknown-bound recovery is serve-only. It may update signed
          // length proofs, but it must never start a body/metadata range until
          // an authoritative re-pin establishes a durable finite bound.
          if (cap === null) return
          pinnedProof = await raceOr(getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true, pinSnapshots: true }))
          const sizeProof = pinnedProof
          const { totalBytes, metaBytes, blobBytes } = sizeProof
          if (!Number.isSafeInteger(totalBytes) || totalBytes < 0 || totalBytes > cap) {
            const recommendedCap = Number.isSafeInteger(totalBytes) ? Math.ceil(totalBytes * 1.25) : null
            this._emitSafely('seed-aborted', {
              appKey: appKeyHex,
              reason: 'maxStorage-too-small',
              recoverable: false,
              driveBytes: totalBytes,
              metaBytes,
              blobBytes,
              cap,
              recommendedCap,
              source,
              hint: 'drive footprint exceeds the durable maxStorage commitment'
            })
            // Clean up — we won't accumulate partial bytes for a drive
            // we can never anchor.
            try { await this.unseedApp(appKeyHex) } catch (_) {}
            return
          }

          // Cancellable download — destroys the download tracker on
          // timeout so its in-flight block requests are released.
          //
          // Two concerns wrapped into one try/catch:
          //   - Reliability v2 (v0.8.13): raceOr arms the LifecycleScope so
          //     stop() can drain mid-download. AbortError exits cleanly.
          //   - Anchor honesty (2026-05-22, AUTO-HEAL-ROOT-CAUSE-...):
          //     do NOT silently treat a download timeout as success.
          //     Track downloadComplete and gate setAnchored below on
          //     blob-core completeness — partial-pin entries must stay
          //     unanchored so runRepairPass keeps re-queuing them.
          let downloadComplete = true
          try {
            // v0.8.28 (#28): pass the LifecycleScope signal through so the
            // inner Promise-shape download path can destroy its blob.core
            // trackers immediately on stop()/self-heal-restart. Without
            // this, raceOr resolves cleanly via AbortError but the inner
            // trackers keep the event loop alive (production-safe but
            // breaks test-runner cleanup; see issue #28).
            await raceOr(this._downloadProvedDriveRanges(drive, sizeProof, {
              timeoutMs: 120_000,
              signal: scope ? scope.signal : null
            }))
          } catch (err) {
            if (isAbortError(err)) return
            downloadComplete = false
          }

          if (aborted() || drive.closed || drive.closing) return

          // After content is downloaded, read manifest and deduplicate.
          // Idempotent — safe to call on retrigger.
          await this._indexAppManifest(appKeyHex, drive, sizeProof)

          // Mark anchored only if the drive is *actually* fully replicated
          // (every blob block present), not just that metadata synced.
          // If we don't have all blocks yet, record an anchor check and
          // let the retry loop / periodic repair monitor keep pulling.
          const fullyReplicated = downloadComplete && this._validAnchoredProof(sizeProof)
          if (fullyReplicated && await this._commitAnchoredProof(appKeyHex, drive, sizeProof)) {
            await this._recordCustodyReceipt(appKeyHex, opts, sizeProof.driveVersion)
            this._emitSafely('anchored', { appKey: appKeyHex, version: sizeProof.driveVersion, source })
            this._emitSafely('reseeded', { appKey: appKeyHex, version: sizeProof.driveVersion, source })
            return
          }

          // Partial pin — let the loop keep trying. recordAnchorCheck
          // updates the timestamp so dashboards see we're working on it.
          if (node.appRegistry && typeof node.appRegistry.recordAnchorCheck === 'function') {
            node.appRegistry.recordAnchorCheck(appKeyHex)
          }
        }
      } catch (err) {
        // AbortError = stop() in progress; exit immediately without retry.
        if (isAbortError(err)) return
        // SESSION_CLOSED / timeout / drive closed mid-call → fall through
        // to the retry delay below if the drive is still considered open.
        if (drive.closed || drive.closing) return
      } finally {
        await this._closeDriveProof(pinnedProof)
      }

      if (attempt < MAX_RETRIES - 1) {
        try {
          if (scope) {
            await scope.sleep(RETRY_DELAYS[attempt])
          } else {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAYS[attempt]))
          }
        } catch (err) {
          // AbortError during the inter-attempt sleep — bail.
          if (isAbortError(err)) return
          throw err
        }
      }
    }
    // Exhausted eager retries — record the check, mark not anchored.
    // The periodic repair monitor will keep trying; this is NOT a
    // permanent failure, just the end of the fast-path attempt.
    if (aborted()) return
    if (node.appRegistry && typeof node.appRegistry.recordAnchorCheck === 'function') {
      node.appRegistry.recordAnchorCheck(appKeyHex)
    }
    this._emitSafely('reseed-error', {
      appKey: appKeyHex,
      error: 'eager-replicate-exhausted',
      recoverable: true,
      source,
      hint: 'periodic repair monitor will keep retrying every 10 min'
    })
  }

  /**
   * Plan the cap used while reopening a persisted registry placeholder.
   * Restart recovery at the stored commitment bypasses new-adoption checks;
   * any incremental commitment still has to pass the same live admission gate
   * as an already-open re-pin. This method does not mutate registry state.
   */
  _preflightRecoveredEntryCap (appKeyHex, existing, newOpts) {
    const oldCap = positiveStorageBound(existing?.maxStorage)
    const hasNewCap = newOpts && Object.prototype.hasOwnProperty.call(newOpts, 'maxStorage') && newOpts.maxStorage !== undefined
    const newCap = positiveStorageBound(newOpts?.maxStorage)

    if (hasNewCap && newCap === null) {
      return {
        ok: false,
        changed: false,
        reason: 'storage-bound-invalid',
        oldCap,
        newCap: null,
        effectiveCap: oldCap
      }
    }

    if (newCap === null || newCap === oldCap) {
      return {
        ok: true,
        changed: false,
        reason: newCap === null ? 'cap-omitted-on-recovery' : 'cap-unchanged',
        oldCap,
        newCap,
        effectiveCap: oldCap
      }
    }

    if (oldCap !== null && newCap < oldCap) {
      const warning = {
        appKey: appKeyHex,
        reason: 'cap-lowered-on-repin',
        oldCap,
        newCap,
        hint: 'Lowering maxStorage on a recovered entry is not honored; relay keeps the higher persisted cap.'
      }
      this._emitSafely('seed-cap-warning', warning)
      return { ok: true, changed: false, effectiveCap: oldCap, ...warning }
    }

    if (oldCap === null) {
      const warning = {
        appKey: appKeyHex,
        reason: 'cap-baseline-unknown-on-repin',
        oldCap,
        newCap,
        incrementalBytes: null,
        effectiveCap: oldCap,
        hint: 'Cannot safely calculate incremental storage for a previously-uncapped recovered entry. Let recovery finish, unseed it, then seed fresh with maxStorage.'
      }
      this._emitSafely('seed-cap-warning', warning)
      return { ok: false, changed: false, ...warning }
    }

    const incrementalBytes = newCap - oldCap

    return {
      ok: true,
      changed: true,
      reason: 'cap-raised',
      oldCap,
      newCap,
      incrementalBytes,
      effectiveCap: newCap
    }
  }

  /**
   * Reconcile new seed opts against an already-seeded entry.
   *
   * v0.8.12 (ask 6 in FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md):
   * before this, seedApp's alreadySeeded path returned early without
   * looking at the new opts. That swallowed re-pins from publishers
   * who hit the v0.8.10 silent-partial-pin bug — their drive sat at
   * partial state forever because the relay's stored cap was too
   * small and the re-pin's larger cap never reached the inner replicate
   * path. Operators had to bounce relays to clear seededApps.
   *
   * Decision table for opts.maxStorage:
   *   new == old (or both null)  → no-op
   *   new omitted, old finite    → no-op; omission does not revoke a cap
   *   new < old                  → emit seed-cap-warning, keep old cap
   *                                (don't shrink already-accepted capacity)
   *   new > old                  → require incremental storage admission,
   *                                then update + retrigger
   *   new set, old was null      → fail closed: the prior commitment is
   *                                unknown, so safe incremental growth cannot
   *                                be calculated
   *
   * Concurrency: an in-flight retrigger is tracked via entry._replicating
   * so rapid re-pins don't stack. If a retrigger is already running, the
   * new cap is updated on the entry but no second replicate is spawned —
   * the in-flight one will see the larger cap via the entry reference.
   * (Caveat: it captured opts.maxStorage at call time; the second-best
   * fallback is the periodic repair monitor, which always uses the
   * latest entry.maxStorage.)
   *
   * Best-effort, non-throwing — failures emit events and return `{ ok:false }`
   * without mutating the cap or starting replication. Caller should not await
   * async replication effects; this returns synchronously after any trigger.
   *
   * @param {string} appKeyHex
   * @param {object} existing - entry from this.seededApps
   * @param {object} newOpts - normalized opts from the new seedApp call
   */
  async _reconcileSeedOptsOnRepin (appKeyHex, existing, newOpts) {
    const node = this.node
    if (!existing) return { ok: false, changed: false, reason: 'repin-entry-missing' }
    if (existing.storageReconciliationRequired || node.storageAdmission?.fatalReason) {
      return { ok: false, changed: false, reason: 'storage-reconciliation-required' }
    }

    const hasNewCap = Object.prototype.hasOwnProperty.call(newOpts || {}, 'maxStorage') && newOpts.maxStorage !== undefined
    const newCap = positiveStorageBound(newOpts?.maxStorage)
    const oldCap = positiveStorageBound(existing.maxStorage)

    if (hasNewCap && newCap === null) {
      return { ok: false, changed: false, reason: 'storage-bound-invalid', oldCap, newCap: null }
    }

    // No cap declared on either side — no change to honor.
    if (newCap === null && oldCap === null) {
      return { ok: true, changed: false, reason: 'cap-not-declared', oldCap, newCap }
    }

    // A re-pin that does not declare maxStorage cannot revoke the relay's
    // existing finite commitment. In particular, do not let null flow into
    // subtraction below: JavaScript would coerce it to zero and manufacture a
    // negative "increment" before clearing the stored cap.
    if (newCap === null) {
      return { ok: true, changed: false, reason: 'cap-omitted-on-repin', oldCap, newCap }
    }

    // Cap unchanged — no-op.
    if (newCap === oldCap) {
      return { ok: true, changed: false, reason: 'cap-unchanged', oldCap, newCap }
    }

    // Cap lowered — emit warning, keep the prior (higher) cap. We don't
    // honor shrinking on re-pin because the publisher already accepted
    // the larger commitment; reducing it now would mean unseeding blocks
    // we already replicated. If the publisher really wants to reduce
    // storage, they should unseedApp first, then seed fresh.
    if (newCap !== null && oldCap !== null && newCap < oldCap) {
      this._emitSafely('seed-cap-warning', {
        appKey: appKeyHex,
        reason: 'cap-lowered-on-repin',
        oldCap,
        newCap,
        hint: 'Lowering maxStorage on already-seeded content is not honored on re-pin; relay keeps the higher prior cap. Unseed first if you want to reduce.'
      })
      return { ok: false, changed: false, reason: 'cap-lowered-on-repin', oldCap, newCap }
    }

    // A legacy unknown baseline can receive a finite bound only after measuring
    // this already-open entry authoritatively. No measurement means serve-only:
    // the operator must unseed and seed fresh rather than pretending old=0.
    let authoritativeSizeBytes = null
    if (oldCap === null) {
      try {
        if (existing.drive) {
          const measured = await getDriveSize(existing.drive, { timeoutMs: 10_000, requireAuthoritative: true })
          authoritativeSizeBytes = measured?.totalBytes
        }
      } catch (_) {
        authoritativeSizeBytes = null
      }
      if (!Number.isSafeInteger(authoritativeSizeBytes) || authoritativeSizeBytes < 0) {
        const warning = {
          appKey: appKeyHex,
          reason: 'cap-baseline-unknown-on-repin',
          oldCap,
          newCap,
          incrementalBytes: null,
          hint: 'Cannot authoritatively measure this legacy entry. Unseed it, then seed fresh with maxStorage.'
        }
        this._emitSafely('seed-cap-warning', warning)
        return { ok: false, changed: false, ...warning }
      }
      if (newCap < authoritativeSizeBytes) {
        const warning = {
          appKey: appKeyHex,
          reason: 'storage-bound-below-actual',
          oldCap,
          newCap,
          actualBytes: authoritativeSizeBytes,
          incrementalBytes: null
        }
        this._emitSafely('seed-cap-warning', warning)
        return { ok: false, changed: false, ...warning }
      }
    }

    const incrementalBytes = oldCap === null ? newCap - authoritativeSizeBytes : newCap - oldCap
    const reservation = node.storageAdmission
      ? node.storageAdmission.reserve(`drive:${appKeyHex}`, newCap, {
        kind: 'drive',
        authoritativeSizeBytes: oldCap === null ? authoritativeSizeBytes : undefined
      })
      : { allowed: false, reason: 'storage-admission-unavailable', availableBytes: 0 }

    if (!reservation || reservation.allowed !== true) {
      const warning = {
        appKey: appKeyHex,
        reason: 'cap-raise-storage-admission-blocked',
        admissionReason: reservation?.reason || 'storage-admission-blocked',
        oldCap,
        newCap,
        incrementalBytes,
        availableBytes: Number.isSafeInteger(reservation?.availableBytes) ? reservation.availableBytes : 0,
        hint: 'Cap raise refused without mutation. Free storage or raise the relay-wide operator cap, then retry.'
      }
      this._emitSafely('seed-cap-warning', warning)
      return { ok: false, changed: false, ...warning }
    }

    // The new commitment becomes externally visible only after an awaited,
    // durable registry write. Any failure restores memory and the previous
    // reservation before returning a terminal failure.
    const previousCap = existing.maxStorage
    let persisted = false
    try {
      if (!node.storageAdmission.owns(reservation)) throw new Error('storage reservation ownership lost before persistence')
      if (!node.appRegistry || typeof node.appRegistry.update !== 'function' ||
          node.appRegistry.update(appKeyHex, { maxStorage: newCap }, { persist: false }) !== true) {
        throw new Error('registry update unavailable')
      }
      if (typeof node.appRegistry.persistEntry === 'function') {
        await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
      } else if (typeof node.appRegistry.flush === 'function') {
        await node.appRegistry.flush({ throwOnError: true })
      } else {
        throw new Error('registry persistence unavailable')
      }
      persisted = true
      if (!node.storageAdmission.commit(reservation)) {
        node.storageAdmission.failClosed()
        return {
          ok: false,
          changed: true,
          durable: true,
          reason: 'storage-reservation-authority-invariant-failed',
          oldCap,
          newCap,
          incrementalBytes
        }
      }
    } catch (err) {
      if (persisted) {
        node.storageAdmission.failClosed()
        return {
          ok: false,
          changed: true,
          durable: true,
          reason: 'storage-reservation-authority-invariant-failed',
          oldCap,
          newCap,
          incrementalBytes,
          error: err && err.message ? err.message : String(err)
        }
      }
      try { node.appRegistry.update(appKeyHex, { maxStorage: previousCap }, { persist: false }) } catch (_) {}
      if (node.storageAdmission) node.storageAdmission.rollback(reservation)
      const warning = {
        appKey: appKeyHex,
        reason: 'cap-raise-persistence-failed',
        oldCap,
        newCap,
        incrementalBytes,
        error: err && err.message ? err.message : String(err)
      }
      this._emitSafely('seed-cap-warning', warning)
      return { ok: false, changed: false, ...warning }
    }

    this._emitSafely('seed-cap-raised', {
      appKey: appKeyHex,
      oldCap,
      newCap,
      incrementalBytes,
      anchored: existing.anchored === true,
      hint: 'Cap raised after storage admission; retriggering replication to drain blocks the prior cap blocked.'
    })

    // Already replicating from a prior call — let it finish. The entry's
    // maxStorage was updated above, so the periodic repair monitor (which
    // reads entry.maxStorage, not the captured opts) will use the new cap
    // on its next sweep if the in-flight call doesn't suffice.
    if (existing._replicating) {
      return {
        ok: true,
        changed: true,
        reason: 'cap-raised',
        oldCap,
        newCap,
        incrementalBytes,
        replicationStarted: false,
        replicationAlreadyRunning: true
      }
    }

    // Drive must be open to retrigger. Stale entry (no drive yet, or drive
    // closed) means seeding is happening elsewhere — let that path finish.
    const drive = existing.drive
    if (!drive || drive.closed || drive.closing) {
      return {
        ok: true,
        changed: true,
        reason: 'cap-raised',
        oldCap,
        newCap,
        incrementalBytes,
        replicationStarted: false
      }
    }

    existing._replicating = true
    const scope = node && node._scope
    const promise = this._eagerReplicate(appKeyHex, drive, { ...newOpts, maxStorage: newCap }, { source: 'repin-cap-raised' })
      .catch((err) => {
        // Swallow AbortError silently; surface unexpected errors so
        // observers see them (same shape as _trackEagerReplicate).
        if (isAbortError(err)) return
        this._emitSafely('reseed-error', {
          appKey: appKeyHex,
          error: (err && err.message) || String(err),
          recoverable: true,
          source: 'repin-cap-raised',
          hint: 'unexpected error in eagerReplicate retrigger; periodic repair monitor will keep retrying'
        })
      })
      .finally(() => {
        // Signal-aware finally: if stop() / unseedApp ran during the
        // replicate and removed the entry, writing _replicating = false
        // would mutate state that no longer should exist (see vector A4
        // in STALE-REF-INVENTORY.md). Re-check the live registry instead
        // of trusting the captured `existing` reference.
        const liveEntry = node.appRegistry ? node.appRegistry.get(appKeyHex) : null
        if (liveEntry && liveEntry === existing) {
          existing._replicating = false
        }
      })
    if (scope) scope.tracked(promise)
    return {
      ok: true,
      changed: true,
      reason: 'cap-raised',
      oldCap,
      newCap,
      incrementalBytes,
      replicationStarted: true
    }
  }

  /**
   * Read manifest.json from a drive and deduplicate by appId.
   * If an older version of the same app is already seeded, unseed it.
   */
  async _indexAppManifest (appKeyHex, drive, proof = null) {
    const node = this.node
    // Blind drives: publisher's privacy contract says "do not inspect."
    // We don't open /manifest.json, don't persist any manifest-derived
    // fields (appId/name/description/author/categories/version), and
    // don't fire app-replaced / app-version-rejected events (which
    // would leak appId+version into logs and the ws-feed). The registry
    // entry keeps its commitment-level fields — appKey, blindContentId,
    // ciphertextRoot, durability, revocable, custodyIntentId — which
    // are signed publisher commitments, not inspected content.
    //
    // See docs/audit/2026-05-19-blind-path-audit.md (Path 1).
    const existingForBlindCheck = node.appRegistry && node.appRegistry.get(appKeyHex)
    if (existingForBlindCheck && existingForBlindCheck.blind === true) return

    let manifestDrive = drive
    let checkout = null
    try {
      if (this._validAnchoredProof(proof) && typeof drive.checkout === 'function') {
        if (!proof.metaCoreSnapshot || !proof.blobCoreSnapshot) {
          throw new Error('manifest proof snapshots unavailable')
        }
        const provedMeta = stableCoreProofState(proof.metaCoreSnapshot)
        const provedBlob = stableCoreProofState(proof.blobCoreSnapshot)
        if (provedMeta.length !== proof.metaLength || provedMeta.fork !== proof.metaFork ||
            provedBlob.length !== proof.blobLength || provedBlob.fork !== proof.blobFork ||
            provedMeta.byteLength + provedBlob.byteLength !== proof.totalBytes) {
          throw new Error('manifest proof snapshot mismatch')
        }
        checkout = drive.checkout(proof.driveVersion)
        if (checkout && typeof checkout.ready === 'function') await checkout.ready()
        const checkoutMeta = stableCoreProofState(checkout?.db?.core)
        if (!checkout || checkout.version !== proof.driveVersion ||
            checkoutMeta.length !== proof.metaLength || checkoutMeta.fork !== proof.metaFork) {
          throw new Error('manifest metadata checkout mismatch')
        }
        // Hyperdrive checkout() pins the metadata Hyperbee but normally reuses
        // the mutable parent blob core. Replace it with the exact blob snapshot
        // that participated in the durable size/fork proof. The non-closing
        // view leaves lifecycle ownership of that snapshot intact.
        checkout.blobs = new Hyperblobs(nonClosingCoreView(proof.blobCoreSnapshot))
        manifestDrive = checkout
      }
      let manifestTimer = null
      let manifestBuf
      try {
        manifestBuf = await Promise.race([
          manifestDrive.get('/manifest.json', { wait: false }),
          new Promise((_resolve, reject) => {
            manifestTimer = setTimeout(() => reject(new Error('manifest timeout')), 5000)
          })
        ])
      } finally {
        if (manifestTimer) clearTimeout(manifestTimer)
      }
      if (!manifestBuf) return

      const manifest = JSON.parse(manifestBuf.toString())
      const manifestAppId = manifest.id || (manifest.name ? manifest.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') : null)
      const version = manifest.version || '0.0.0'
      const manifestType = normalizeContentType(
        manifest.contentType ||
        manifest.hiverelay?.contentType ||
        manifest.hiverelay?.type ||
        manifest.type,
        null
      )
      const existing = node.appRegistry.get(appKeyHex)
      const contentType = manifestType || normalizeContentType(existing?.type, 'app')
      const appId = manifestAppId || existing?.appId || null
      const parentKey = isValidHexKey(manifest.parentKey, 64)
        ? manifest.parentKey
        : existing?.parentKey || null
      const mountPath = typeof manifest.mountPath === 'string' && manifest.mountPath.trim().startsWith('/')
        ? manifest.mountPath.trim()
        : existing?.mountPath || null

      // Update this entry's metadata via the registry
      node.appRegistry.update(appKeyHex, {
        type: contentType,
        parentKey,
        mountPath,
        appId,
        version,
        privacyTier: manifest.privacyTier || manifest.privacy?.tier || manifest.privacy?.mode || undefined,
        storageClass: normalizeStorageClass(
          manifest.storageClass || manifest.hiverelay?.storageClass,
          existing?.storageClass || (existing?.blind ? 'temporary' : 'persistent')
        ),
        availabilityClass: normalizeAvailabilityClass(
          manifest.availabilityClass || manifest.hiverelay?.availabilityClass,
          existing?.availabilityClass || (existing?.blind ? 'atomic-handoff' : 'always-on')
        ),
        name: manifest.name || appId,
        description: manifest.description || '',
        author: manifest.author || null,
        categories: manifest.categories || null,
        // v0.17.0: optional display icon from the app's manifest, for
        // catalog/PearBrowser tiles. Accept manifest.icon or icons[0].
        icon: manifest.icon || (Array.isArray(manifest.icons) ? manifest.icons[0] : null) || null
      })

      if (contentType !== 'app') return
      if (!appId) return

      // Check for version conflicts with existing apps
      const conflict = node.appRegistry.checkConflict(appId, appKeyHex, version)
      if (conflict.conflict) {
        if (conflict.shouldReplace) {
          this._emitSafely('app-replaced', {
            appId,
            oldKey: conflict.existingKey,
            oldVersion: conflict.existingVersion,
            newKey: appKeyHex,
            newVersion: version
          })
          await this.unseedApp(conflict.existingKey)
        } else {
          this._emitSafely('app-version-rejected', {
            appId,
            rejectedKey: appKeyHex,
            rejectedVersion: version,
            currentKey: conflict.existingKey,
            currentVersion: conflict.existingVersion
          })
          await this.unseedApp(appKeyHex)
        }
      }
    } catch (_) {
      // No manifest or parse error — skip deduplication silently
    } finally {
      if (checkout && checkout !== drive) {
        try { await checkout.close() } catch (_) {}
      }
    }
  }

  /**
   * One-shot repair attempt for a single unanchored drive.
   * Triggered by:
   *   - the periodic repair loop (every config.repairInterval ms)
   *   - immediate trigger when a peer relay's catalog reports anchored:true
   *     for a drive we have but haven't anchored
   *
   * Uses the existing drive instance + swarm membership — no need to
   * rejoin discovery topics. Just tries `drive.update + drive.download`
   * with a short timeout. If any peer (original publisher OR another
   * relay) has blocks for this drive, we pull them.
   *
   * Returns true if the drive was successfully anchored on this attempt.
   */
  async repairUnanchored (appKeyHex, opts = {}) {
    const node = this.node
    if (!node.appRegistry) return false
    if (node.appRegistry.physicalReadOnly === true) return false
    const entry = node.appRegistry.get(appKeyHex)
    if (!entry || !entry.drive) return false
    if (entry.anchored === true) return true // already anchored, nothing to do
    const cap = positiveStorageBound(entry.maxStorage)
    if (cap === null) return false

    const drive = entry.drive
    if (drive.closed || drive.closing) return false

    // LifecycleScope integration: every long await participates in the
    // cancellation contract so stop() can drain in-flight repair attempts
    // (Tier B vectors B4/B5/B16 in STALE-REF-INVENTORY.md). When the
    // scope is missing (test harness without a RelayNode), behavior
    // falls back to the original raw-await path.
    const scope = node && node._scope
    if (scope && scope.aborted) return false
    const raceOr = (promise) => scope ? scope.race(promise) : promise

    const updateTimeout = opts.updateTimeout || 15_000
    const downloadTimeout = opts.downloadTimeout || 60_000

    // Re-announce on the discovery topic in case the swarm dropped us
    try {
      this._joinDriveDiscovery(appKeyHex, drive.discoveryKey)
      await raceOr(Promise.race([
        node.swarm.flush().catch(() => {}),
        new Promise(resolve => {
          const t = setTimeout(resolve, 2000)
          if (t.unref) t.unref()
        })
      ]))
    } catch (err) {
      if (isAbortError(err)) return false
      /* swarm-leave-during-repair race */
    }

    if ((scope && scope.aborted) || drive.closed || drive.closing) return false

    try {
      // Cancellable update — see cancellable-drive-update.js. On timeout,
      // detaches in-flight hypercore upgrade refs from activeRequests so
      // they don't leak.
      await raceOr(updateWithTimeout(drive, { timeoutMs: updateTimeout }))
    } catch (err) {
      if (isAbortError(err)) return false
      this._emitSafely('repair-update-failed', { appKey: appKeyHex, error: err.message })
      return false
    }

    if ((scope && scope.aborted) || drive.closed || drive.closing || drive.version === 0) {
      // Still no version — no peer has data for this drive yet
      if (typeof node.appRegistry.recordAnchorCheck === 'function') {
        node.appRegistry.recordAnchorCheck(appKeyHex)
      }
      return false
    }

    // Signed metadata + blob tree lengths cover the complete Hyperdrive
    // footprint. Do not open any content range if the current version exceeds
    // the durable commitment.
    let sizeProof
    try {
      sizeProof = await raceOr(getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true, pinSnapshots: true }))
      const measured = sizeProof
      if (!Number.isSafeInteger(measured?.totalBytes) || measured.totalBytes < 0 || measured.totalBytes > cap) {
        this._emitSafely('seed-aborted', {
          appKey: appKeyHex,
          reason: 'maxStorage-too-small',
          driveBytes: measured?.totalBytes ?? null,
          cap,
          source: 'repair'
        })
        await this._closeDriveProof(sizeProof)
        return false
      }
    } catch (err) {
      await this._closeDriveProof(sizeProof)
      if (isAbortError(err)) return false
      return false
    }

    // We have metadata; pull blob content (cancellable on timeout).
    //
    // 2026-05-22: same fix as _eagerReplicate — don't mark anchored on a
    // partial download. The repair loop is the safety net that pulls
    // missing blocks over time; if we declare victory on the first
    // attempt, runRepairPass will skip this entry forever and the gap
    // never closes. Return false on partial; the next repair tick will
    // pull more blocks and eventually the full-replication check passes.
    let downloadComplete = true
    try {
      try {
        // Reliability v2 (v0.8.13): raceOr arms the LifecycleScope so
        // stop() can drain mid-download. AbortError exits cleanly.
        // Anchor honesty (2026-05-22): don't silently treat a timeout
        // as success — flag downloadComplete=false so the partial-pin
        // gate below keeps the entry unanchored and runRepairPass
        // re-queues it on the next tick.
        // v0.8.28 (#28): same scope-signal threading as _eagerReplicate
        // — destroy inner blob.core trackers on scope abort.
        await raceOr(this._downloadProvedDriveRanges(drive, sizeProof, {
          timeoutMs: downloadTimeout,
          signal: scope ? scope.signal : null
        }))
      } catch (err) {
        if (isAbortError(err)) return false
        downloadComplete = false
      }

      if ((scope && scope.aborted) || drive.closed || drive.closing) return false

      if (downloadComplete && this._validAnchoredProof(sizeProof) &&
          await this._commitAnchoredProof(appKeyHex, drive, sizeProof)) {
        await this._recordCustodyReceipt(appKeyHex, entry, sizeProof.driveVersion)
        this._emitSafely('anchored', { appKey: appKeyHex, version: sizeProof.driveVersion, source: 'repair' })
        return true
      }

      // Partial pin — record the attempt and signal to the caller that
      // we're not done. The next repair tick re-queues this entry and
      // tries again with a fresh download tracker.
      if (typeof node.appRegistry.recordAnchorCheck === 'function') {
        node.appRegistry.recordAnchorCheck(appKeyHex)
      }
    } catch (err) {
      if (isAbortError(err)) return false
      this._emitSafely('repair-download-failed', { appKey: appKeyHex, error: err.message })
    } finally {
      await this._closeDriveProof(sizeProof)
    }
    return false
  }

  /**
   * Verify that a hyperdrive's blob core is fully present locally —
   * every block from 0..length-1 has been downloaded. This is the
   * proper definition of "anchored": we can actually serve the
   * content to a peer that asks. Returns true for empty drives
   * (no blob blocks needed); returns false if the drive is closed,
   * if the blob layer hasn't loaded yet, or if any block is missing.
   *
   * Was previously implicit and incorrect: the old code took
   * `drive.version > 0` (metadata length) as proof of anchoring,
   * which let the partial-pin failure mode persist indefinitely
   * because the periodic repair monitor skips anchored entries.
   * See docs/AUTO-HEAL-ROOT-CAUSE-2026-05-22.md.
   *
   * @param {Hyperdrive} drive
   * @returns {Promise<boolean>}
   */
  async _isDriveFullyReplicated (drive, opts = {}) {
    if (!drive || drive.closed || drive.closing) return false

    // 2026-05-24: hard timeout on the whole check. drive.getBlobs() can
    // hang indefinitely on a freshly-loaded entry whose blob layer
    // hasn't been resolved by any peer yet (the lazy init awaits a
    // hypercore replication session that may never come). Without a
    // timeout, a single such entry deadlocks the entire _runAnchorCheck
    // sequential loop — observed live on milkyb-iad where the first
    // anchor pass at startup processed 5 of 145 entries, then hung
    // forever on entry 6. 15h uptime, 144 entries never checked again.
    //
    // Default 3s is generous: getBlobs() resolves in milliseconds when
    // it works at all. If it doesn't resolve quickly, the drive's blob
    // layer isn't accessible from any current peer, so we should return
    // false (treat as not-fully-replicated) and move on so the loop
    // can keep making progress on other entries. Next pass will retry.
    const timeoutMs = Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
      ? Math.floor(opts.timeoutMs)
      : 3000

    let timer
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => resolve('__TIMEOUT__'), timeoutMs)
      if (timer.unref) timer.unref()
    })

    try {
      const result = await Promise.race([this._isDriveFullyReplicatedInner(drive), timeout])
      if (result === '__TIMEOUT__') return false
      return result === true
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  // Inner implementation — extracted so _isDriveFullyReplicated can
  // wrap it in a timeout race without duplicating the logic. Pre-2026-
  // 05-24 this was the body of _isDriveFullyReplicated directly.
  async _isDriveFullyReplicatedInner (drive) {
    const blobs = drive.blobs || (typeof drive.getBlobs === 'function'
      ? await drive.getBlobs().catch(() => null)
      : null)
    const blobCore = blobs && blobs.core
    if (!blobCore) return false
    const length = blobCore.length
    if (!Number.isFinite(length) || length < 0) return false
    if (length === 0) return true // metadata-only drive — nothing to download
    try {
      // core.has(0, length) walks the bitfield for the first unset bit
      // in [0, length); returns true only if every block is present.
      return await blobCore.has(0, length)
    } catch (_) {
      return false
    }
  }

  /**
   * Repair loop — scan all unanchored entries and try to pull blocks
   * for each. Run by RelayNode's periodic repair interval. Returns
   * { checked, repaired, stillUnanchored } so callers can emit
   * observability events.
   *
   * @param {object} opts
   * @param {number} [opts.maxConcurrent=3] - parallel repair attempts
   * @param {number} [opts.budget=null] - cap on entries to try this pass
   */
  async runRepairPass (opts = {}) {
    const node = this.node
    if (!node.appRegistry) return { checked: 0, repaired: 0, stillUnanchored: 0 }
    if (node.appRegistry.physicalReadOnly === true) {
      return { checked: 0, repaired: 0, stillUnanchored: 0 }
    }
    const scope = node && node._scope
    if (scope && scope.aborted) return { checked: 0, repaired: 0, stillUnanchored: 0 }

    const maxConcurrent = Math.max(1, opts.maxConcurrent || 3)
    const budget = opts.budget || Infinity
    const queue = []

    for (const [appKey, entry] of node.appRegistry.apps) {
      if (queue.length >= budget) break
      if (entry.anchored === true) continue
      if (!entry.drive || entry.drive.closed || entry.drive.closing) continue
      queue.push(appKey)
    }

    let repaired = 0
    let checked = 0

    // Worker pool — process queue with bounded concurrency. Workers drop
    // the remaining queue on scope abort so a long repair pass doesn't
    // keep firing fresh `drive.update`s against a tearing-down corestore.
    const workers = Array.from({ length: maxConcurrent }, () => (async () => {
      while (queue.length > 0) {
        if (scope && scope.aborted) return
        const appKey = queue.shift()
        if (!appKey) return
        checked++
        try {
          const ok = await this.repairUnanchored(appKey)
          if (ok) repaired++
        } catch (err) {
          if (isAbortError(err)) return
          this._emitSafely('repair-error', { appKey, error: err.message })
        }
      }
    })())
    await Promise.all(workers)

    const stillUnanchored = checked - repaired
    return { checked, repaired, stillUnanchored }
  }

  /**
   * Record a custody receipt for an ALREADY-seeded app when a re-pin carries a
   * custody intent. The first-seed flow anchors the receipt at the end of
   * _seedAppInner (after the content drive replicates); an app that is already
   * seeded never re-enters that path. The canonical gap: a publisher calls
   * client.publish() — which auto-seeds the content drive — and THEN
   * splitForCustody(), which POSTs /seed carrying the custodyIntentId. By then
   * the addressKey is already in seededApps, so seedApp short-circuits
   * ({ alreadySeeded:true }) and no PVSS share receipt is ever anchored. The
   * dealer's _awaitVerifiedReceipts then polls a quorum that never forms and
   * every live split times out (CUSTODY_QUORUM_TIMEOUT).
   *
   * Fire-and-forget by design: the /seed HTTP response must not block on a
   * share-bundle replication that can take seconds, exactly as the first-seed
   * path returns before the async anchor completes — the dealer polls for the
   * receipt either way. Fail-closed for PVSS (a share that doesn't verify
   * yields no receipt) and idempotent (recordCustodyReceipt is keyed
   * intentId→relayPubkey, so a repeated re-pin just overwrites the same slot).
   *
   * @param {string} appKeyHex
   * @param {object} existing - entry from this.seededApps
   * @param {object} opts - normalized opts from the new (re-pin) seedApp call
   */
  _recordCustodyReceiptOnRepin (appKeyHex, existing, opts) {
    if (!opts || opts.blind !== true || !opts.custodyIntentId) return
    const node = this.node
    const version = Number.isFinite(opts.contentVersion)
      ? opts.contentVersion
      : (existing && Number.isFinite(existing.version) ? existing.version : 0)
    const promise = this._recordCustodyReceipt(appKeyHex, opts, version)
      .catch((err) => {
        this._emitSafely('custody-receipt-error', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          error: (err && err.message) || String(err)
        })
        return null
      })
    const scope = node && node._scope
    if (scope && typeof scope.tracked === 'function') scope.tracked(promise)
  }

  async _recordCustodyReceipt (appKeyHex, opts = {}, contentVersion = 0) {
    const node = this.node
    if (!opts.blind || !opts.custodyIntentId || !node.seedingRegistry || !node.swarm?.keyPair) return null

    // PVSS share custody (v2). If the bound intent declares a share scheme,
    // this relay must PUBLICLY verify the encrypted share it was assigned —
    // no secret key — before anchoring a receipt. SD2: a failed (or
    // unavailable) verification must NOT anchor; emit
    // `custody:share-verify-failed` and skip the receipt so this relay is not
    // counted toward the publisher's reconstruction quorum. The content drive
    // it replicated stays served regardless — share custody is an added layer.
    let pvssFields = null
    let intent = null
    try {
      intent = typeof node.seedingRegistry.getCustodyIntent === 'function'
        ? node.seedingRegistry.getCustodyIntent(opts.custodyIntentId)
        : null
    } catch (_) { intent = null }

    // Fail closed: if EITHER the signed intent declares share custody, or the
    // (unsigned) seed request hints at it via opts.shareScheme, this is a PVSS
    // custody and must be share-verified. The seed hint can only make us
    // non-anchor more often, never wrongly anchor — so if the publisher said
    // "PVSS" but the signed intent isn't loaded yet, we decline rather than
    // anchor a plain receipt that the transition check would later reject.
    const wantsPvss = !!(intent && intent.shareScheme) || !!opts.shareScheme
    if (wantsPvss) {
      if (!intent || !intent.shareScheme) {
        this._emitSafely('custody:share-verify-failed', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          shareBundleKey: null,
          reason: 'intent-unavailable'
        })
        return null
      }
      const relayPubkey = b4a.toString(node.swarm.keyPair.publicKey, 'hex')
      const bundle = await this._readShareBundle(intent.shareBundleKey, { appKey: appKeyHex })
      const result = verifyShareBundleForRelay(intent, bundle, relayPubkey)
      if (!result.ok) {
        this._emitSafely('custody:share-verify-failed', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          shareBundleKey: intent.shareBundleKey || null,
          reason: result.reason
        })
        return null
      }
      pvssFields = {
        version: 2,
        shareScheme: result.shareScheme,
        commitmentRoot: result.commitmentRoot,
        shareIndex: result.shareIndex,
        shareCommitment: result.shareCommitment,
        shareVerified: true
      }
    }

    try {
      const receipt = await node.seedingRegistry.recordCustodyReceipt({
        intentId: opts.custodyIntentId,
        addressKey: appKeyHex,
        blindContentId: opts.blindContentId,
        ciphertextRoot: opts.ciphertextRoot,
        contentVersion: Number.isFinite(opts.contentVersion) ? opts.contentVersion : contentVersion,
        relayRegion: node.config.region || 'unknown',
        shardIds: Array.isArray(opts.shardIds) ? opts.shardIds : [],
        anchored: true,
        retainUntil: opts.retainUntil || (Date.now() + 30 * 24 * 60 * 60 * 1000),
        ...(pvssFields || {})
      }, node.swarm.keyPair)
      this._emitSafely('custody-receipt', { appKey: appKeyHex, intentId: opts.custodyIntentId, receipt })
      return receipt
    } catch (err) {
      this._emitSafely('custody-receipt-error', {
        appKey: appKeyHex,
        intentId: opts.custodyIntentId,
        error: err.message || String(err)
      })
      return null
    }
  }

  /**
   * Replicate + read a public PVSS share bundle from its hypercore key.
   *
   * The publisher writes the bundle (commitments[] + encryptedShares[]) to a
   * sibling hypercore as a single JSON block and names that core's key in the
   * signed v2 custody intent (shareBundleKey). The relay joins the core's swarm
   * topic — the corestore's `connection` handler already replicates every core
   * it holds — and reads block 0, which `core.get` waits for until a peer
   * supplies it (or the timeout fires).
   *
   * Best-effort + non-throwing: any failure (malformed key, no peers, timeout,
   * unparseable block) returns null, and the caller treats a null bundle as an
   * unverifiable share — so it does not anchor (SD2). Read-once: the topic is
   * left and the core session closed in `finally`, so no swarm/topic state
   * leaks past the verification.
   *
   * @param {string} shareBundleKey 64-hex hypercore key
   * @param {{timeoutMs?:number}} [opts]
   * @returns {Promise<object|null>} parsed { commitments, encryptedShares } or null
   */
  async _readShareBundle (shareBundleKey, opts = {}) {
    const node = this.node
    const appKey = isValidHexKey(opts.appKey, 64) ? opts.appKey.toLowerCase() : null
    if (!isValidHexKey(shareBundleKey, 64) || !appKey || !node.swarm) return null
    if (!opts[TRACKED_STORAGE_MUTATION] && node.storageAdmission?.runKeyMutation) {
      return node.storageAdmission.runKeyMutation(`drive:${appKey}`, () => this._readShareBundle(shareBundleKey, {
        ...opts,
        appKey,
        [TRACKED_STORAGE_MUTATION]: true
      }))
    }
    if (node.storageAdmission && !node.storageAdmission.mutationAdmission().allowed) return null
    if (node.storageAdmission && (typeof node.storageAdmission.canAcknowledge !== 'function' ||
        !node.storageAdmission.canAcknowledge(`drive:${appKey}`))) return null
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 30_000
    let core = null
    let auxStore = null
    let auxPath = null
    let onConnection = null
    let discovery = null
    let tracker = null
    let snapshotCore = null
    let ownedResource = null
    let readError = null
    const withTimeout = (promise, label) => {
      let timer = null
      return Promise.race([
        Promise.resolve(promise),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error(label + ' timeout')), timeoutMs)
        })
      ]).finally(() => { if (timer) clearTimeout(timer) })
    }
    try {
      if (typeof opts.createAuxStore === 'function') {
        auxStore = await opts.createAuxStore()
      } else {
        if (!node.config || typeof node.config.storage !== 'string') return null
        const parent = join(node.config.storage, '.aux-share-bundles')
        auxPath = join(parent, appKey)
        await mkdir(parent, { recursive: true })
        // One deterministic slot per admitted drive. Crash leftovers are
        // deleted before reuse; concurrent/retry calls serialize on aux:appKey.
        await rm(auxPath, { recursive: true, force: true })
        await mkdir(auxPath, { recursive: true })
        auxStore = new Corestore(auxPath)
      }
      if (!auxStore || typeof auxStore.get !== 'function') return null
      if (node.storageAdmission && (typeof node.storageAdmission.canAcknowledge !== 'function' ||
          !node.storageAdmission.canAcknowledge(`drive:${appKey}`))) return null
      if (typeof auxStore.ready === 'function') await auxStore.ready()
      onConnection = (conn) => {
        try { auxStore.replicate(conn) } catch (_) {}
      }
      if (node.connections && typeof node.connections.keys === 'function') {
        for (const conn of node.connections.keys()) onConnection(conn)
      }
      if (typeof node.swarm.on === 'function') node.swarm.on('connection', onConnection)
      core = auxStore.get({ key: b4a.from(shareBundleKey, 'hex') })
      await core.ready()
      // Pull-only join; the swarm 'connection' handler replicates the store.
      discovery = node.swarm.join(core.discoveryKey, { server: false, client: true })
      ownedResource = {
        appKey,
        core,
        discovery,
        auxStore,
        auxPath,
        onConnection,
        tracker: null,
        snapshotCore: null
      }
      this._auxShareBundleResources.add(ownedResource)
      if (discovery && typeof discovery.flushed === 'function') {
        await Promise.race([
          discovery.flushed().catch(() => {}),
          new Promise(resolve => setTimeout(resolve, Math.min(timeoutMs, 5_000)))
        ])
      }
      const activeRequests = []
      try {
        await withTimeout(core.update({ wait: true, activeRequests }), 'share bundle proof')
      } finally {
        if (activeRequests.length > 0 && core.replicator?.clearRequests) {
          try { core.replicator.clearRequests(activeRequests, new Error('SHARE_BUNDLE_PROOF_CANCELLED')) } catch (_) {}
        }
      }
      let snapshot = null
      for (let attempt = 0; attempt < 4; attempt++) {
        const forkBefore = Number(core.fork ?? 0)
        const lengthBefore = Number(core.length)
        const byteLength = Number(core.byteLength)
        const lengthAfter = Number(core.length)
        const forkAfter = Number(core.fork ?? 0)
        if (Number.isSafeInteger(lengthBefore) && lengthBefore === 1 && lengthAfter === 1 &&
            Number.isSafeInteger(forkBefore) && forkBefore >= 0 && forkBefore === forkAfter &&
            Number.isSafeInteger(byteLength) && byteLength >= 0 && byteLength <= STORAGE_SHARE_BUNDLE_MAX_BYTES) {
          snapshot = { length: lengthAfter, byteLength, fork: forkAfter }
          break
        }
      }
      if (!snapshot) return null
      if (typeof core.snapshot !== 'function') return null
      snapshotCore = core.snapshot({ wait: false })
      ownedResource.snapshotCore = snapshotCore
      if (typeof snapshotCore.ready === 'function') await snapshotCore.ready()
      const pinned = stableCoreProofState(snapshotCore)
      if (pinned.length !== snapshot.length || pinned.byteLength !== snapshot.byteLength || pinned.fork !== snapshot.fork) {
        return null
      }
      tracker = snapshotCore.download({ start: 0, end: 1 })
      ownedResource.tracker = tracker
      const settled = typeof tracker?.done === 'function'
        ? tracker.done()
        : (typeof tracker?.downloaded === 'function' ? tracker.downloaded() : null)
      if (!settled) return null
      await withTimeout(settled, 'share bundle range')
      // The one finite proved range is local now; wait:false prevents get()
      // from silently becoming another network/materialization operation.
      const block = await snapshotCore.get(0, { wait: false })
      if (!block) return null
      if (!Number.isSafeInteger(block.byteLength) || block.byteLength > STORAGE_SHARE_BUNDLE_MAX_BYTES) return null
      if (node.storageAdmission && (typeof node.storageAdmission.canAcknowledge !== 'function' ||
          !node.storageAdmission.canAcknowledge(`drive:${appKey}`))) return null
      const parsed = JSON.parse(b4a.toString(block))
      return parsed && typeof parsed === 'object' ? parsed : null
    } catch (err) {
      readError = err
      return null
    } finally {
      if (ownedResource) {
        if (readError) ownedResource.readCause = readError
        await this._releaseAuxShareBundleResource(ownedResource)
      } else {
        if (tracker && typeof tracker.destroy === 'function') await Promise.resolve(tracker.destroy())
        if (snapshotCore) await snapshotCore.close()
        if (discovery && typeof discovery.destroy === 'function') await discovery.destroy()
        if (core) await core.close()
        if (onConnection && typeof node.swarm.removeListener === 'function') {
          node.swarm.removeListener('connection', onConnection)
        }
        if (auxStore && typeof auxStore.close === 'function') await auxStore.close()
        if (auxPath) await rm(auxPath, { recursive: true, force: true })
      }
    }
  }

  /**
   * Tear down a seeded app's live resources (drive, swarm topic, download
   * ranges).
   *
   * @param {string} appKeyHex
   * @param {object} [opts]
   * @param {boolean} [opts.forget=true] - when true (the default, used by
   *   operator/P2P unseed, eviction, and custody-retire), the registry
   *   entry is deleted and the deletion is persisted. When false, used by
   *   stop()'s shutdown loop, the entry is KEPT on disk and only its live
   *   in-memory refs (drive/discoveryKey/downloadRanges) are dropped, so a
   *   subsequent start()/reseedFromRegistry repopulates it. Deleting on a
   *   clean shutdown was a data-loss bug — every restart erased the
   *   registry.
   */
  async unseedApp (appKeyHex, opts = {}) {
    if (!isValidHexKey(appKeyHex)) throw new Error('Invalid app key: must be 64 hex characters')
    appKeyHex = appKeyHex.toLowerCase()
    const forget = opts.forget !== false
    const node = this.node
    if (forget && typeof node.appRegistry?.assertDurableWritesAvailable === 'function') {
      node.appRegistry.assertDurableWritesAvailable()
    }
    if (forget && !opts[TRACKED_STORAGE_REMOVAL] && node.storageAdmission?.runKeyMutation) {
      return node.storageAdmission.runKeyMutation(`drive:${appKeyHex}`, () => this.unseedApp(appKeyHex, {
        ...opts,
        [TRACKED_STORAGE_REMOVAL]: true
      }))
    }
    let owner = this._retiringDrives.get(appKeyHex)
    if (!owner) {
      const entry = node.appRegistry.get(appKeyHex)
      if (!entry) return
      entry.retiring = true
      owner = {
        appKey: appKeyHex,
        entry,
        rejected: false,
        forget,
        evictedAt: opts.evictedAt,
        bridgeRegistered: !!node.distributedDriveBridge
      }
      this._retiringDrives.set(appKeyHex, owner)
    } else {
      if (forget) owner.forget = true
      if (Number.isSafeInteger(opts.evictedAt) && opts.evictedAt > 0) {
        owner.evictedAt = Number.isSafeInteger(owner.evictedAt)
          ? Math.max(owner.evictedAt, opts.evictedAt)
          : opts.evictedAt
      }
    }
    await this._settleRetiringDrive(owner)
  }

  /**
   * Register persistent download ranges on a drive's metadata + blob
   * cores so they actively request missing blocks from any peer that
   * has them, continuously, between repair-tick windows.
   *
   * Stored on entry.downloadRanges so unseedApp can destroy them
   * cleanly before drive.close (avoids leaking replicator refs into
   * the closing core's session pool).
   *
   * Idempotent — calling twice on the same entry destroys the previous
   * ranges and registers fresh ones (e.g. when the blob core wasn't
   * ready on the first attempt and we want to retry after some blocks
   * land).
   *
   * Best-effort + non-throwing — failures emit a
   * persistent-download-error event instead. The drive remains
   * registered + serving whatever blocks it has; only the active-pull
   * optimisation is lost.
   *
   * @param {string} appKeyHex
   * @param {Hyperdrive} drive
   * @returns {Promise<void>}
   */
  async _registerPersistentDownloads (appKeyHex, drive, tracked = false) {
    const node = this.node
    if (!tracked && node.storageAdmission?.runKeyMutation) {
      return node.storageAdmission.runKeyMutation(`drive:${appKeyHex}`, () =>
        this._registerPersistentDownloads(appKeyHex, drive, true))
    }
    const entry = node.appRegistry && node.appRegistry.get(appKeyHex)
    if (!entry) return
    if (!drive || drive.closed || drive.closing) return
    const cap = positiveStorageBound(entry.maxStorage)
    if (cap === null) return
    let settleRegistration = null
    const token = {
      settled: new Promise(resolve => { settleRegistration = resolve })
    }
    entry.downloadRegistration = token
    let measured = null
    try {
      measured = await getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true, pinSnapshots: true })
      if (node.appRegistry.get(appKeyHex) !== entry || entry.drive !== drive ||
          entry.downloadRegistration !== token || drive.closed || drive.closing) return
      if (!Number.isSafeInteger(measured?.totalBytes) || measured.totalBytes < 0 || measured.totalBytes > cap) {
        this._emitSafely('persistent-download-error', {
          appKey: appKeyHex,
          error: 'drive footprint exceeds durable maxStorage bound'
        })
        return
      }
      await this._installPersistentDownloadProof(appKeyHex, drive, measured)
    } finally {
      try {
        await this._closeDriveProof(measured)
      } finally {
        if (entry.downloadRegistration === token) entry.downloadRegistration = null
        settleRegistration()
      }
    }
  }

  /**
   * Authenticated unseed: verify the publisher signature before unseeding.
   * The publisher must sign (appKey + 'unseed' + timestamp) with the key
   * that originally published the app (stored in appRegistry.publisherPubkey).
   */
  verifyUnseedRequest (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    const node = this.node

    // Defensive input validation — keep this verifier total (never throws),
    // matching the convention of the other verify-style helpers. It is reached
    // from the P2P unseed path and from direct callers; without this a wrong-
    // length signature makes sodium assert and a non-integer timestamp makes
    // BigInt() throw. The HTTP API validates these at its boundary already, so
    // this changes behaviour only for inputs that previously threw.
    if (!isValidHexKey(appKeyHex, 64) || !isValidHexKey(publisherPubkeyHex, 64) ||
        !isValidHexKey(signatureHex, 128) || !Number.isSafeInteger(timestamp) || timestamp < 0) {
      return { ok: false, error: 'MALFORMED_REQUEST' }
    }

    const entry = node.appRegistry.get(appKeyHex)
    if (!entry) return { ok: false, error: 'APP_NOT_FOUND' }

    // Verify the publisher key matches the one that seeded the app
    if (entry.publisherPubkey && entry.publisherPubkey !== publisherPubkeyHex) {
      return { ok: false, error: 'PUBLISHER_MISMATCH' }
    }

    // If no publisher was stored (legacy app), reject the unseed —
    // operator must use /unseed with API key instead
    if (!entry.publisherPubkey) {
      return { ok: false, error: 'NO_PUBLISHER_KEY: app has no recorded publisher — operator must unseed via /unseed with API key' }
    }

    // Revocability commitment check.
    //
    // If the publisher signed a non-revocable seed request (revocable=false),
    // they relinquished publisher-side unseed authority at seed time. Honor
    // that commitment — reject the unseed even with a valid signature.
    //
    // The operator retains takedown authority via the management API. They
    // own the storage; the publisher agreed to not be able to retract once
    // committed. This is the asymmetry that makes the flag meaningful.
    if (entry.revocable === false) {
      return {
        ok: false,
        error: 'NON_REVOCABLE: publisher relinquished unseed authority at seed time — only operator-side unseed via management API will remove this content'
      }
    }

    // Unseed-freeze period check. If the publisher committed to a cooldown
    // window (e.g. 24 hours after seed before unseed is honored), enforce
    // it. Acts as a "commit then think" safety valve for cases where the
    // publisher wants strong commitments but not absolute permanence.
    if (entry.unseedFreezeMs && entry.unseedFreezeMs > 0) {
      const seededAt = entry.startedAt || 0
      const earliestUnseed = seededAt + entry.unseedFreezeMs
      if (Date.now() < earliestUnseed) {
        const remaining = earliestUnseed - Date.now()
        return {
          ok: false,
          error: `UNSEED_FROZEN: publisher committed to ${entry.unseedFreezeMs}ms freeze; ${remaining}ms remaining before unseed is honored`
        }
      }
    }

    // Check timestamp freshness (reject if older than 5 minutes)
    const age = Date.now() - timestamp
    if (age > 5 * 60 * 1000 || age < -60_000) {
      return { ok: false, error: 'STALE_TIMESTAMP' }
    }

    // Verify Ed25519 signature over (appKey + 'unseed' + timestamp)
    const appKeyBuf = b4a.from(appKeyHex, 'hex')
    const pubkeyBuf = b4a.from(publisherPubkeyHex, 'hex')
    const sigBuf = b4a.from(signatureHex, 'hex')

    const tsBuf = b4a.alloc(8)
    const tsView = new DataView(tsBuf.buffer, tsBuf.byteOffset)
    tsView.setBigUint64(0, BigInt(timestamp))

    const payload = b4a.concat([appKeyBuf, b4a.from('unseed'), tsBuf])
    const valid = sodium.crypto_sign_verify_detached(sigBuf, payload, pubkeyBuf)

    if (!valid) return { ok: false, error: 'INVALID_SIGNATURE' }
    return { ok: true }
  }

  /**
   * Broadcast an unseed request to all connected peers via P2P.
   */
  broadcastUnseed (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    const node = this.node
    if (!node._seedProtocol) return
    node._seedProtocol.publishUnseedRequest(
      b4a.from(appKeyHex, 'hex'),
      b4a.from(publisherPubkeyHex, 'hex'),
      b4a.from(signatureHex, 'hex'),
      timestamp
    )
  }
}
