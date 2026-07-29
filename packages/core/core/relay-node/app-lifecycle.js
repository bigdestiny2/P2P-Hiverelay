import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { updateWithTimeout, getDriveSize } from './cancellable-drive-update.js'
import { isAbortError } from './lifecycle-scope.js'
import { verifyShareBundleForRelay } from '../pvss.js'
import { STORAGE_SHARE_BUNDLE_MAX_BYTES } from '../../config/storage-admission-authority.js'
import { positiveStorageBound } from '../../config/storage-cap.js'
import { hashReleaseTree, verifyAppRelease } from '../release-lifecycle.js'
import { EvictionManager } from './eviction.js'
import { compareSupersessionEntries } from './dedup-report.js'
import {
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'

// Capability marker used only by durable registry recovery. A Symbol keeps
// external callers from forging the serve-only path through JSON/options.
const STORAGE_RECOVERY_INGRESS = Symbol('storage-recovery-ingress')

function findManifestConflict (appRegistry, appId, appKey, version, release = null) {
  let selected = null
  for (const [candidateKey, entry] of appRegistry.apps) {
    if (candidateKey === appKey || !entry || normalizeContentType(entry.type, 'app') !== 'app' || entry.appId !== appId) continue
    const candidateVersion = entry.version || '0.0.0'
    if (!selected || compareSupersessionEntries(entry, selected.entry) > 0) {
      selected = { key: candidateKey, version: candidateVersion, entry }
    }
  }
  if (!selected) return { conflict: false }
  return {
    conflict: true,
    existingKey: selected.key,
    existingVersion: selected.version,
    existingEntry: selected.entry,
    shouldReplace: compareSupersessionEntries({ version, release }, selected.entry) >= 0
  }
}

function releaseContextError (release, context) {
  if (release.driveKey !== context.appKey) return 'release driveKey does not match the seeded drive'
  if (release.appId !== context.appId) return 'release appId does not match manifest id'
  if (release.version !== context.version) return 'release version does not match manifest version'
  if (context.seedPublisher && release.publisherPubkey !== context.seedPublisher.toLowerCase()) {
    return 'release publisher does not match signed seed publisher'
  }
  if (context.maxStorage && release.storageBudgetBytes !== context.maxStorage) {
    return 'release storage budget does not match seed storage bound'
  }
  if (context.priorRelease) {
    const prior = context.priorRelease
    if (release.signature === prior.signature) return null
    if (release.publisherPubkey !== prior.publisherPubkey) return 'release publisher changed on the same drive'
    if (release.sequence <= prior.sequence) return 'release sequence did not advance'
    if (release.generation !== prior.generation) return 'release generation changed without key rotation'
    if (release.previousDriveKey !== null) return 'same-drive release cannot declare a predecessor'
  }
  return null
}

function seedAdmissionTimeoutError (timeoutMs) {
  const err = new Error(`Seed admission timed out after ${timeoutMs}ms`)
  err.code = 'STORAGE_SEED_ADMISSION_TIMEOUT'
  return err
}

function seedAdmissionAbortError () {
  const err = new Error('Seed admission aborted')
  err.name = 'AbortError'
  err.code = 'ABORT_ERR'
  return err
}

function stableCoreProofState (core, attempts = 4) {
  if (!core) return null
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
  return null
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
    this._seedMutex = false
    // Serialization tail for seed admission. Callers queue behind it via
    // _queueSeedAdmission; the tail itself never rejects, so stop paths can
    // `await lifecycle._seedTail` to know the chain has drained.
    this._seedTail = Promise.resolve()
    // Drives whose live resources (ranges, drive, bridge) have been settled
    // but whose durable delete has not yet completed. On failure the entry is
    // restored to the registry and parked here so a retry can finish the
    // retirement without re-closing already-settled resources.
    this._retiringDrives = new Map()
    // Active auxiliary share-bundle fetches. unseedApp drains these before
    // releasing drive debt so a concurrent fetch cannot race with teardown.
    this._auxShareBundleResources = new Set()
    // Drive keys whose storage lease this lifecycle already holds, so a
    // re-entrant call (seed → evict → unseed) doesn't deadlock on the
    // non-reentrant per-key mutation lock.
    this._heldDriveLeases = new Set()
  }

  /**
   * The seededApps Map. Delegates to the AppRegistry so existing external
   * callers that reach into node.seededApps keep seeing the same instance.
   */
  get seededApps () {
    return this.node.appRegistry.apps
  }

  async _reclaimReleaseRollback ({ appId, publisherPubkey, retainKeys }) {
    const node = this.node
    let manager = node.eviction || null
    if (!manager && node.store) {
      manager = new EvictionManager({
        appRegistry: node.appRegistry,
        seedingRegistry: node.seedingRegistry || {},
        storageAccounting: node.storageAccounting || { getBytes: () => null },
        diskMonitor: node.diskMonitor || {},
        getReplicationHealth: () => new Map(),
        myPubkeyHex: 'release-retention',
        unseed: (appKeyHex, opts) => this.unseedApp(appKeyHex, opts),
        store: node.store
      })
    }
    if (!manager || typeof manager.reclaimSuperseded !== 'function') return null
    return manager.reclaimSuperseded({
      dryRun: false,
      appId,
      publisherPubkey,
      retainKeys
    })
  }

  _joinDriveDiscovery (appKeyHex, discoveryKey, handles = null) {
    const handle = this.node.swarm.join(discoveryKey, { server: true, client: true })
    const entry = this.node.appRegistry.get(appKeyHex)
    const owned = entry && entry.discoveryHandles instanceof Set
      ? entry.discoveryHandles
      : (handles instanceof Set ? handles : null)
    if (owned) owned.add(handle)
    return handle
  }

  /**
   * Serialize a seed-admission closure behind every earlier one.
   *
   * Why a queue and not a spin-wait mutex: a caller that gives up (timeout)
   * or a node that is shutting down (scope abort) must ALSO cancel the work
   * it queued. The old `while (this._seedMutex) await sleep(50)` loop could
   * not do that — the waiter's closure still ran when the mutex freed, so a
   * seed that had already reported failure to its caller went on to mutate
   * the registry and storage-admission ledger afterwards.
   *
   * Cancellation only applies while a closure is WAITING. Once it starts it
   * owns the admission slot and runs to completion; aborting mid-seed would
   * strand a half-registered drive, which is exactly what the retirement
   * owner in unseedApp exists to avoid.
   *
   * @param {() => Promise<any>} run  the admission-critical closure
   * @returns {Promise<any>} the closure's result, or a rejection with code
   *   `STORAGE_SEED_ADMISSION_TIMEOUT` / `ABORT_ERR` if it never ran.
   */
  _queueSeedAdmission (run) {
    const node = this.node || {}
    const scope = node._scope || null
    const signal = scope && scope.signal ? scope.signal : null
    const configured = Number(node.config && node.config.seedAdmissionTimeoutMs)
    const timeoutMs = Number.isFinite(configured) && configured > 0 ? configured : 0

    const gate = { started: false, cancelled: false }
    let resolveCaller = null
    let rejectCaller = null
    const caller = new Promise((resolve, reject) => {
      resolveCaller = resolve
      rejectCaller = reject
    })

    let timer = null
    let onAbort = null
    const disarm = () => {
      if (timer) { clearTimeout(timer); timer = null }
      if (onAbort && signal) { signal.removeEventListener('abort', onAbort); onAbort = null }
    }
    const cancel = (err) => {
      if (gate.started || gate.cancelled) return
      gate.cancelled = true
      disarm()
      rejectCaller(err)
    }

    const previous = this._seedTail || Promise.resolve()
    this._seedTail = previous.then(async () => {
      if (gate.cancelled) return
      gate.started = true
      disarm()
      try {
        resolveCaller(await run())
      } catch (err) {
        rejectCaller(err)
      }
    })

    if (signal && signal.aborted) {
      cancel(seedAdmissionAbortError())
    } else {
      // Deliberately NOT unref'd: a caller is blocked on this timeout, so the
      // event loop must stay alive long enough to deliver it. It is cleared as
      // soon as the closure starts or the wait is cancelled, so it can only
      // hold the process for at most seedAdmissionTimeoutMs.
      if (timeoutMs > 0) timer = setTimeout(() => cancel(seedAdmissionTimeoutError(timeoutMs)), timeoutMs)
      if (signal) {
        onAbort = () => cancel(seedAdmissionAbortError())
        signal.addEventListener('abort', onAbort, { once: true })
      }
    }

    return caller
  }

  /**
   * Load the durable drive registry (and run the one-shot seeded-apps.json
   * migration when empty). Does NOT re-seed drives — callers that need the
   * drives back online after start() await this, then fire-and-forget
   * reseedDrives(entries). Seals storage-admission drive recovery so
   * writable services cannot open before the inventory is known.
   */
  async loadRegistry () {
    const node = this.node
    const entries = await node.appRegistry.load()
    if (node.storageAdmission) {
      for (const entry of entries) {
        if (!entry || !entry.appKey) continue
        if (typeof node.storageAdmission.adoptRecovery === 'function') {
          node.storageAdmission.adoptRecovery(`drive:${entry.appKey}`, entry.maxStorage, { kind: 'drive' })
        }
      }
    }
    if (!entries.length) {
      await this.migrateOldSeededApps()
      const migrated = typeof node.appRegistry.entries === 'function'
        ? [...node.appRegistry.entries()].map(([appKey, entry]) => ({ appKey, ...entry }))
        : []
      if (node.storageAdmission && typeof node.storageAdmission.markRecoveryReady === 'function') {
        node.storageAdmission.markRecoveryReady('drives')
      }
      return migrated
    }
    if (node.storageAdmission && typeof node.storageAdmission.markRecoveryReady === 'function') {
      node.storageAdmission.markRecoveryReady('drives')
    }
    return entries
  }

  /**
   * Re-seed drives for previously-persisted registry entries. Safe to run
   * fire-and-forget after start(); each seedApp cascades into eagerReplicate.
   */
  async reseedDrives (entries) {
    if (!Array.isArray(entries) || !entries.length) return
    for (const entry of entries) {
      if (!entry || !entry.appKey) continue
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
          maxStorage: Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
            ? entry.maxStorage
            : undefined,
          leaseManaged: entry.leaseManaged === true
        })
        this._safeEmit('reseeded', { appKey: entry.appKey })
      } catch (err) {
        this._safeEmit('reseed-error', { appKey: entry.appKey, error: err })
      }
    }
  }

  /**
   * Emit without letting a throwing observer truncate the caller OR starve
   * later observers of the same event. Node's EventEmitter stops calling the
   * remaining listeners for an event the moment one throws; recovery loops
   * cannot tolerate that (a buggy 'reseed-error' handler would silently drop
   * the event for every well-behaved listener after it). Call each listener
   * in its own try/catch so all observers receive the event.
   */
  _safeEmit (event, payload) {
    const listeners = this.listeners(event)
    for (const listener of listeners) {
      try {
        listener.call(this, payload)
      } catch (err) {
        // Continue to the remaining observers. Surface the failure on a
        // separate throw-free channel so operators still see it.
        try { this.emit('observer-error', { event, error: err }) } catch (_) {}
      }
    }
  }

  /**
   * Combined load + reseed. Retained for callers (e.g. bare-relay) that want
   * the whole recovery in one await.
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
    try {
      const oldPath = join(node.config.storage, 'seeded-apps.json')
      const data = JSON.parse(await readFile(oldPath, 'utf8'))
      const entries = Array.isArray(data) ? data : []
      if (!entries.length) return

      for (const entry of entries) {
        const appKey = entry.appKey
        if (!appKey) continue
        try {
          await this.seedApp(appKey, {
            [STORAGE_RECOVERY_INGRESS]: true,
            appId: entry.appId || null,
            type: entry.type || 'app',
            parentKey: entry.parentKey || null,
            mountPath: entry.mountPath || null,
            version: entry.version || null,
            privacyTier: entry.privacyTier || null
          })
          this.emit('reseeded', { appKey, source: 'migration' })
        } catch (err) {
          this.emit('reseed-error', { appKey, error: err })
        }
      }
    } catch (_) {
      // No old file — fresh install
    }
  }

  async seedApp (appKeyHex, opts = {}) {
    const node = this.node
    // Recovery inventories have not sealed, so the relay does not yet know
    // what it already owns — admitting new content here could double-count
    // storage against a commitment the recovery pass is about to adopt.
    // Checked before every other gate (including "seeding not enabled") so
    // the caller gets the specific, retryable cause rather than a generic
    // refusal that hides the fact that startup simply hasn't finished.
    if (node._storageIngressReady === false && opts[STORAGE_RECOVERY_INGRESS] !== true) {
      const err = new Error('storage recovery inventory has not sealed')
      err.code = 'STORAGE_RECOVERY_INVENTORY_PENDING'
      throw err
    }
    if (!node.seeder) throw new Error('Seeding not enabled')
    if (!isValidHexKey(appKeyHex)) throw new Error('Invalid app key: must be 64 hex characters')
    // Canonicalize before ANYTHING keys off it. AppRegistry stores lowercase,
    // so a mixed-case caller otherwise misses the live entry, seeds a second
    // drive for the same content, and serializes under a different
    // storage-admission mutation key than the call it is racing.
    appKeyHex = appKeyHex.toLowerCase()

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
    const mutationKey = `drive:${appKeyHex}`
    return this._withDriveLease(appKeyHex, () => this._seedAppAdmitted(
      appKeyHex, normalizedOpts, contentType, parentKey, mountPath, privacyTier, mutationKey
    ))
  }

  /**
   * Run `run` while holding this drive's per-key storage lease.
   *
   * The same lease is taken by seedApp, unseedApp, the PVSS auxiliary fetch,
   * and HyperGateway's HTTP reads, so a durable retirement cannot begin while
   * a stalled HTTP response is still reading pinned core sessions, and a new
   * read cannot enter after retirement starts.
   *
   * runKeyMutation is NOT re-entrant, so a held key is tracked and re-entered
   * directly — a seed that evicts and unseeds the same key would otherwise
   * wait on a lock it is itself holding.
   */
  /**
   * True when the registry can accept a durable write right now. Non-throwing
   * probe used to stop storage-PRODUCING work (seed, repair) early while still
   * allowing serve-only paths to run under a read-only physical authority.
   */
  _durableWritesAvailable () {
    const registry = this.node && this.node.appRegistry
    if (!registry || typeof registry.assertDurableWritesAvailable !== 'function') return true
    try {
      registry.assertDurableWritesAvailable()
      return true
    } catch (_) {
      return false
    }
  }

  _withDriveLease (appKeyHex, run, opts = {}) {
    const admission = this.node && this.node.storageAdmission
    if (!admission || typeof admission.runKeyMutation !== 'function') return run()
    if (this._heldDriveLeases.has(appKeyHex)) return run()
    // stop() retires every seeded drive AFTER the authority stops accepting
    // mutations, and runKeyMutation fails closed in that state. Gating a
    // retirement on it would leave shutdown unable to close its own drives.
    // Seeds keep failing closed here — refusing new content while storage is
    // stopping is the correct answer; refusing to release it is not.
    if (opts.allowWhenStopping && typeof admission.mutationAdmission === 'function' &&
        admission.mutationAdmission().allowed !== true) {
      return run()
    }
    return admission.runKeyMutation(`drive:${appKeyHex}`, async () => {
      this._heldDriveLeases.add(appKeyHex)
      try {
        return await run()
      } finally {
        this._heldDriveLeases.delete(appKeyHex)
      }
    })
  }

  /**
   * seedApp's body, already serialized on this drive's storage-admission
   * mutation key. Split out so the already-seeded fast path runs UNDER that
   * lock: evaluating it outside lets two concurrent callers both conclude the
   * drive needs seeding.
   */
  async _seedAppAdmitted (appKeyHex, normalizedOpts, contentType, parentKey, mountPath, privacyTier, mutationKey) {
    const node = this.node

    // Fail before ANY storage adoption. Seeding ends in a durable registry
    // write, so if the physical authority cannot accept one there is no point
    // opening a Corestore session, building a Hyperdrive, or taking a storage
    // reservation first — each of those is a resource we would then have to
    // unwind, and the reservation error (STORAGE_ADMISSION_BLOCKED) would
    // mask the real cause.
    if (normalizedOpts[STORAGE_RECOVERY_INGRESS] !== true &&
        node.appRegistry && typeof node.appRegistry.assertDurableWritesAvailable === 'function') {
      node.appRegistry.assertDurableWritesAvailable()
    }

    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
        // Returning alreadySeeded ACKNOWLEDGES durable state to the caller.
        // That is only honest if the storage ledger holds a committed record
        // for this drive. When admission cannot acknowledge, the live entry is
        // stale relative to durable state (crash between the registry write
        // and the ledger commit, or a fail-closed authority) — reconcile
        // instead of reporting a success nothing durable backs.
        if (node.storageAdmission && typeof node.storageAdmission.canAcknowledge === 'function' &&
            !node.storageAdmission.canAcknowledge(mutationKey)) {
          const err = new Error('seeded drive storage authority requires reconciliation')
          err.code = 'STORAGE_RECONCILIATION_REQUIRED'
          throw err
        }
        const dkHex = typeof existing.discoveryKey === 'string'
          ? existing.discoveryKey
          : b4a.toString(existing.discoveryKey, 'hex')
        const reconcile = await this._reconcileSeedOptsOnRepin(appKeyHex, existing, normalizedOpts)
        if (reconcile && reconcile.ok === false && reconcile.reason && reconcile.reason.startsWith('cap-raise-storage-admission')) {
          const err = new Error('Storage cap blocks re-pin cap raise: ' + reconcile.admissionReason)
          err.code = 'STORAGE_CAP_REPIN_BLOCKED'
          err.repin = reconcile
          throw err
        }
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, normalizedOpts)
        this._refreshExistingSeed(appKeyHex, existing, normalizedOpts)
        return { discoveryKey: dkHex, alreadySeeded: true }
      }
      // else: placeholder entry from load() — fall through to seed properly.
    }

    // Serialize against concurrent eviction races. Queued (not yet started)
    // admissions are cancellable by shutdown or by seedAdmissionTimeoutMs, so
    // a caller that has already been told "no" never mutates state later.
    return this._queueSeedAdmission(async () => {
      this._seedMutex = true
      try {
        return await this._seedAppInner(appKeyHex, normalizedOpts, contentType, parentKey, mountPath, privacyTier)
      } finally {
        this._seedMutex = false
      }
    })
  }

  async _seedAppInner (appKeyHex, opts, contentType, parentKey, mountPath, privacyTier) {
    const node = this.node
    const recoveringEntry = this.seededApps.get(appKeyHex) || null
    const recoveringExisting = recoveringEntry !== null
    const readOnlyRecovery = recoveringExisting &&
      opts[STORAGE_RECOVERY_INGRESS] === true &&
      node.appRegistry.physicalReadOnly === true

    // Re-check after acquiring mutex — another call may have seeded it.
    // Same null-discoveryKey guard + v0.8.12 opts reconcile as the
    // pre-mutex check in seedApp().
    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
        const dkHex = typeof existing.discoveryKey === 'string'
          ? existing.discoveryKey
          : b4a.toString(existing.discoveryKey, 'hex')
        const reconcile = await this._reconcileSeedOptsOnRepin(appKeyHex, existing, opts)
        if (reconcile && reconcile.ok === false && reconcile.reason && reconcile.reason.startsWith('cap-raise-storage-admission')) {
          const err = new Error('Storage cap blocks re-pin cap raise: ' + reconcile.admissionReason)
          err.code = 'STORAGE_CAP_REPIN_BLOCKED'
          err.repin = reconcile
          throw err
        }
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, opts)
        this._refreshExistingSeed(appKeyHex, existing, opts)
        return { discoveryKey: dkHex, alreadySeeded: true }
      }
      // else: placeholder entry from load() — fall through.
    }

    // Storage admission gate: a fresh seed must pass the admission check
    // before any drive is created or swarm joined. This is the hard cap
    // that prevents a relay from accepting content it cannot durably host.
    const admissionCap = Number.isFinite(opts.maxStorage) && opts.maxStorage > 0
      ? Math.floor(opts.maxStorage)
      : null
    if (!recoveringExisting && admissionCap === null) {
      const err = new Error('positive safe-integer maxStorage is required')
      err.code = 'STORAGE_BOUND_REQUIRED'
      throw err
    }
    let admissionReservation = null
    if (!readOnlyRecovery && node.storageAdmission && typeof node.storageAdmission.reserve === 'function' && admissionCap !== null) {
      const reservation = node.storageAdmission.reserve(`drive:${appKeyHex}`, admissionCap)
      if (!reservation || reservation.allowed !== true) {
        const err = new Error('Storage admission blocked: ' + (reservation && reservation.reason))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
      // Held in the `reserved` state until the drive exists AND its registry
      // entry is durably persisted, then committed below. EVERY exit path
      // between here and that commit must roll it back, so the eviction check
      // and the Hyperdrive construction moved inside the try below — both can
      // throw, and a reservation abandoned in `reserved` state is not merely a
      // leaked byte count: reserve() rejects the next attempt on this key with
      // `storage-reservation-in-progress` and canAcknowledge() stays false, so
      // the drive can never be re-seeded, re-pinned, or acknowledged again.
      admissionReservation = reservation
    }

    let drive = null
    const discoveryHandles = new Set()
    try {
      // Evict oldest app if storage capacity would be exceeded
      if (node.config.enableEviction !== false && node.seeder && node.seeder.totalBytesStored >= node.config.maxStorageBytes && this.seededApps.size > 0) {
        const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000
        let oldestKey = null
        let oldestTime = Infinity

        for (const [appKey, entry] of this.seededApps) {
          if (entry.startedAt < oldestTime) {
            oldestTime = entry.startedAt
            oldestKey = appKey
          }
        }

        const shouldEvict = oldestKey && (
          (opts.replicationFactor && opts.replicationFactor > (this.seededApps.get(oldestKey)?.replicationFactor || 1)) ||
          (Date.now() - oldestTime > TWENTY_FOUR_HOURS)
        )

        if (shouldEvict) {
          await node._evictOldestApp()
        } else {
          throw new Error('Storage capacity exceeded and no eligible app to evict')
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
      drive = new Hyperdrive(node.store.session(), appKey)

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

      // Signal that we're looking for peers for this drive's cores
      const done = drive.findingPeers ? drive.findingPeers() : null
      this._joinDriveDiscovery(appKeyHex, discoveryKey, discoveryHandles)
      try {
        await node.swarm.flush()
        if (admissionReservation) {
          // A fresh remote Hyperdrive does not know its blob-core key until
          // the metadata feed has synchronized. Asking getBlobs() first can
          // therefore time out even while the publisher is correctly serving
          // the drive (the PVSS dealer→relay path exercises this exact race).
          await updateWithTimeout(drive, { timeoutMs: 10_000 })
          const measured = await getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true })
          if (!Number.isSafeInteger(measured.totalBytes) || measured.totalBytes < 0) {
            const err = new Error('DRIVE_SIZE_UNRESOLVED')
            err.code = 'STORAGE_SIZE_PROOF_UNAVAILABLE'
            throw err
          }
          if (measured.totalBytes > admissionCap) {
            const err = new Error('maxStorage is below the authoritative drive size')
            err.code = 'STORAGE_BOUND_BELOW_ACTUAL'
            err.actualBytes = measured.totalBytes
            err.boundBytes = admissionCap
            throw err
          }
        }
      } finally {
        if (done) done()
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
      const maxStorage = Number.isFinite(opts.maxStorage) && opts.maxStorage > 0
        ? Math.floor(opts.maxStorage)
        : null

      // Captured before the write so a failed durable persist can restore the
      // exact pre-seed view (usually the null-discoveryKey placeholder that
      // load() created), rather than leaving a half-seeded entry behind.
      const previousEntry = node.appRegistry.get(appKeyHex) || null
      const nextEntry = {
        drive,
        discoveryKey,
        discoveryHandles,
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
        release: opts.release || null,
        revocable,
        unseedFreezeMs,
        durability,
        maxStorage
      }
      if (readOnlyRecovery) {
        if (typeof node.appRegistry.attachRuntime !== 'function' ||
            node.appRegistry.attachRuntime(appKeyHex, {
              drive,
              discoveryKey,
              discoveryHandles,
              bytesServed: 0,
              retiring: false
            }) !== true) {
          throw new Error('APP_REGISTRY_RUNTIME_ATTACH_FAILED')
        }
      } else {
        node.appRegistry.set(appKeyHex, nextEntry, { persist: false })
      }

      // Durability gate: persist EXPLICITLY and await it before reporting the
      // seed as successful. AppRegistry.set() persists fire-and-forget, so a
      // failed durable write used to be swallowed — seedApp returned a
      // discoveryKey, the drive served traffic, and the entry simply was not
      // there after the next restart. On failure, restore the pre-seed view
      // and rethrow; the enclosing catch closes the drive.
      if (!readOnlyRecovery && typeof node.appRegistry.persistEntry === 'function') {
        try {
          await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
        } catch (err) {
          if (previousEntry) node.appRegistry.set(appKeyHex, previousEntry, { persist: false })
          else node.appRegistry.delete(appKeyHex, { persist: false })
          throw err
        }
      }

      // Durable state now exists for this drive, so the reservation becomes a
      // committed commitment. Ordered AFTER persistEntry for the same reason
      // _reconcileSeedOptsOnRepin commits last: a crash between the persist and
      // the commit leaves a durable entry that startup re-adopts via
      // adoptRecovery(), whereas committing first would leave a commitment in
      // the ledger with no durable entry backing it.
      //
      // owns() guards the commit because commit() on a token this authority no
      // longer holds trips failClosed() and wedges the whole relay.
      if (admissionReservation && typeof node.storageAdmission.owns === 'function' &&
          node.storageAdmission.owns(admissionReservation)) {
        node.storageAdmission.commit(admissionReservation)
        admissionReservation = null
      }

      // Start exact-state replication only after both durable registry
      // persistence and storage-authority commitment are visible.
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
          this.emit('persistent-download-error', {
            appKey: appKeyHex,
            error: err.message || String(err)
          })
        })
      }

      if (node.distributedDriveBridge) {
        try { node.distributedDriveBridge.registerDrive(appKeyHex, drive) } catch (_) {}
      }

      this.emit('seeding', { appKey: appKeyHex, discoveryKey: b4a.toString(discoveryKey, 'hex') })
      return { discoveryKey: b4a.toString(discoveryKey, 'hex') }
    } catch (err) {
      // Drive first (it may not exist yet — the eviction check and the
      // Hyperdrive constructor both throw with `drive` still null), then undo
      // the admission reservation so a failed seed leaves the ledger exactly as
      // it found it.
      for (const handle of discoveryHandles) {
        try { if (handle && typeof handle.destroy === 'function') await handle.destroy() } catch (_) {}
      }
      if (drive) { try { await drive.close() } catch (_) {} }
      this._rollbackSeedAdmission(admissionReservation)
      throw err
    }
  }

  /**
   * Undo a still-reserved drive admission from _seedAppInner's failure paths.
   *
   * rollback() — not release() — is reserve()'s counterpart. rollback restores
   * the token's `previous` record, which on the reseed-a-placeholder path is
   * the adoptRecovery() commitment made for this drive at startup. release()
   * would delete that record outright, dropping a durable commitment from the
   * ledger and understating the relay's storage debt by the drive's whole cap.
   *
   * owns() guards the call so a reservation that was already committed (or
   * superseded by another holder) is left alone rather than clobbered.
   */
  _rollbackSeedAdmission (reservation) {
    const node = this.node
    if (!reservation || !node || !node.storageAdmission) return
    const authority = node.storageAdmission
    if (typeof authority.rollback !== 'function' || typeof authority.owns !== 'function') return
    try {
      if (authority.owns(reservation)) authority.rollback(reservation)
    } catch (_) {}
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
        this.emit('reseed-error', {
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

  _refreshExistingSeed (appKeyHex, existing, opts) {
    const drive = existing?.drive
    if (!drive || drive.closed || drive.closing || existing._replicating) return false
    existing._replicating = true
    this._trackEagerReplicate(appKeyHex, drive, opts, { source: 'repin-refresh' })
      .finally(() => { existing._replicating = false })
    return true
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
      trackers.push(core.download({ start: 0, end }))
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
        try { tracker.destroy() } catch {}
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
        try { await core.close() } catch {}
      }
    }
    if (proof) {
      proof.metaCoreSnapshot = null
      proof.blobCoreSnapshot = null
    }
  }

  async _installPersistentDownloadProof (appKeyHex, drive, proof) {
    const entry = this.node.appRegistry && this.node.appRegistry.get(appKeyHex)
    if (!entry || entry.drive !== drive || !this._validAnchoredProof(proof) ||
        !proof.metaCoreSnapshot || !proof.blobCoreSnapshot) return false

    const metaState = stableCoreProofState(proof.metaCoreSnapshot)
    const blobState = stableCoreProofState(proof.blobCoreSnapshot)
    if (!metaState || !blobState ||
        metaState.length !== proof.metaLength || metaState.fork !== proof.metaFork ||
        blobState.length !== proof.blobLength || blobState.fork !== proof.blobFork ||
        metaState.byteLength + blobState.byteLength !== proof.totalBytes) return false

    const nextRanges = []
    try {
      nextRanges.push(proof.metaCoreSnapshot.download({ start: 0, end: proof.metaLength }))
      nextRanges.push(proof.blobCoreSnapshot.download({ start: 0, end: proof.blobLength }))
    } catch (err) {
      for (const range of nextRanges) {
        try { range.destroy() } catch {}
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
      try { if (range && typeof range.destroy === 'function') range.destroy() } catch {}
    }
    for (const core of previousCores) {
      try { if (core && typeof core.close === 'function') await core.close() } catch {}
    }
    return true
  }

  async _commitAnchoredProof (appKeyHex, drive, proof, tracked = false) {
    const node = this.node
    if (!tracked) {
      return this._withDriveLease(appKeyHex, () => this._commitAnchoredProof(appKeyHex, drive, proof, true))
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
      this.emit('persistent-download-error', {
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
    const initialBound = node.appRegistry && node.appRegistry.get(appKeyHex)?.maxStorage
    const initialCap = positiveStorageBound(initialBound ?? opts.maxStorage)
    if (initialCap === null) return

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
          // The admission contract must remain finite for the entire pin.
          // If a concurrent registry mutation removes/corrupts the bound,
          // stop without anchoring and let reconciliation repair policy.
          if (cap === null) return
          pinnedProof = await raceOr(
            getDriveSize(drive, { timeoutMs: 10_000, requireAuthoritative: true, pinSnapshots: true })
          )
          const { totalBytes, metaBytes, blobBytes } = pinnedProof
          if (!Number.isSafeInteger(totalBytes) || totalBytes < 0 || totalBytes > cap) {
            const recommendedCap = Number.isSafeInteger(totalBytes) ? Math.ceil(totalBytes * 1.25) : null
            this.emit('seed-aborted', {
              appKey: appKeyHex,
              reason: 'maxStorage-too-small',
              recoverable: false,
              driveBytes: totalBytes,
              metaBytes,
              blobBytes,
              cap,
              recommendedCap,
              source,
              hint: 'drive is ' + totalBytes + ' bytes; publisher should re-seed with maxStorage ≥ ' + recommendedCap
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
            await raceOr(this._downloadProvedDriveRanges(drive, pinnedProof, {
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
          await this._indexAppManifest(appKeyHex, drive)

          // Mark anchored only if the drive is *actually* fully replicated
          // (every blob block present), not just that metadata synced.
          // If we don't have all blocks yet, record an anchor check and
          // let the retry loop / periodic repair monitor keep pulling.
          const fullyReplicated = downloadComplete && this._validAnchoredProof(pinnedProof)
          const anchored = fullyReplicated && await this._commitAnchoredProof(appKeyHex, drive, pinnedProof)
          if (anchored) {
            const anchoredVersion = pinnedProof.driveVersion
            await this._recordCustodyReceipt(appKeyHex, opts, anchoredVersion)
            this.emit('anchored', { appKey: appKeyHex, version: anchoredVersion, source })
            this.emit('reseeded', { appKey: appKeyHex, version: anchoredVersion, source })
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
    this.emit('reseed-error', {
      appKey: appKeyHex,
      error: 'eager-replicate-exhausted',
      recoverable: true,
      source,
      hint: 'periodic repair monitor will keep retrying every 10 min'
    })
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
   *   new < old                  → emit seed-cap-warning, keep old cap
   *                                (don't shrink already-accepted capacity)
   *   new > old (or new is set,  → update entry.maxStorage, retrigger
   *               old was null)    _eagerReplicate to drain blocks that
   *                                the old cap had blocked
   *
   * Concurrency: an in-flight retrigger is tracked via entry._replicating
   * so rapid re-pins don't stack. If a retrigger is already running, the
   * new cap is updated on the entry but no second replicate is spawned —
   * the in-flight one will see the larger cap via the entry reference.
   * (Caveat: it captured opts.maxStorage at call time; the second-best
   * fallback is the periodic repair monitor, which always uses the
   * latest entry.maxStorage.)
   *
   * Best-effort, non-throwing — failures emit events instead. Caller
   * should not await this method's effects (it returns synchronously
   * after kicking off any async work).
   *
   * @param {string} appKeyHex
   * @param {object} existing - entry from this.seededApps
   * @param {object} newOpts - normalized opts from the new seedApp call
   */
  _preflightRecoveredEntryCap (appKeyHex, existing, newOpts) {
    const oldCap = positiveStorageBound(existing?.maxStorage)
    const hasNewCap = newOpts && Object.prototype.hasOwnProperty.call(newOpts, 'maxStorage') && newOpts.maxStorage !== undefined
    const newCap = positiveStorageBound(newOpts?.maxStorage)

    if (hasNewCap && newCap === null) {
      return { ok: false, changed: false, reason: 'storage-bound-invalid', oldCap, newCap: null, effectiveCap: oldCap }
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
      this._safeEmit('seed-cap-warning', warning)
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
      this._safeEmit('seed-cap-warning', warning)
      return { ok: false, changed: false, ...warning }
    }

    const incrementalBytes = newCap - oldCap
    return { ok: true, changed: true, reason: 'cap-raised', oldCap, newCap, incrementalBytes, effectiveCap: newCap }
  }

  async _reconcileSeedOptsOnRepin (appKeyHex, existing, newOpts) {
    const node = this.node
    if (!existing) return { ok: false, changed: false, reason: 'no-existing-entry' }

    const hasNewCap = newOpts && Object.prototype.hasOwnProperty.call(newOpts, 'maxStorage') && newOpts.maxStorage !== undefined
    const newCap = Number.isFinite(newOpts.maxStorage) && newOpts.maxStorage > 0
      ? Math.floor(newOpts.maxStorage)
      : null
    const oldCap = Number.isFinite(existing.maxStorage) && existing.maxStorage > 0
      ? Math.floor(existing.maxStorage)
      : null

    // Explicitly-provided invalid cap (0, negative, NaN) fails closed.
    if (hasNewCap && newCap === null) {
      return { ok: false, changed: false, reason: 'storage-bound-invalid', oldCap, newCap: null, effectiveCap: oldCap }
    }

    // Omitted cap (null) with a finite prior cap → preserve the old cap.
    if (newCap === null && oldCap !== null) {
      return { ok: true, changed: false, reason: 'cap-omitted-on-repin' }
    }

    // No cap declared on either side — nothing to reconcile.
    if (newCap === null && oldCap === null) {
      return { ok: true, changed: false, reason: 'no-cap-declared' }
    }

    // Cap unchanged — no-op.
    if (newCap === oldCap) {
      return { ok: true, changed: false, reason: 'cap-unchanged' }
    }

    // Cap lowered — emit warning, keep the prior (higher) cap.
    if (newCap !== null && oldCap !== null && newCap < oldCap) {
      this._safeEmit('seed-cap-warning', {
        appKey: appKeyHex,
        reason: 'cap-lowered-on-repin',
        oldCap,
        newCap,
        hint: 'Lowering maxStorage on already-seeded content is not honored on re-pin; relay keeps the higher prior cap. Unseed first if you want to reduce.'
      })
      return { ok: false, changed: false, reason: 'cap-lowered-on-repin', oldCap, newCap }
    }

    // Cap newly declared where old baseline is unknown → fail closed.
    // We can't compute incremental growth from an unknown baseline.
    if (newCap !== null && oldCap === null) {
      this._safeEmit('seed-cap-warning', {
        appKey: appKeyHex,
        reason: 'cap-baseline-unknown-on-repin',
        oldCap: null,
        newCap
      })
      return { ok: false, changed: false, reason: 'cap-baseline-unknown-on-repin', incrementalBytes: null }
    }

    // Cap raised — admission-gate the incremental growth before mutating.
    const incrementalBytes = newCap - oldCap
    if (node.storageAdmission && typeof node.storageAdmission.reserve === 'function') {
      const reservation = node.storageAdmission.reserve(`drive:${appKeyHex}`, newCap)
      if (!reservation || reservation.allowed !== true) {
        this._safeEmit('seed-cap-warning', {
          appKey: appKeyHex,
          reason: 'cap-raise-storage-admission-blocked',
          oldCap,
          newCap,
          incrementalBytes,
          admissionReason: reservation && reservation.reason
        })
        return {
          ok: false,
          changed: false,
          reason: 'cap-raise-storage-admission-blocked',
          admissionReason: reservation && reservation.reason,
          incrementalBytes
        }
      }
      // Persist the cap update BEFORE committing the reservation so a crash
      // between persist and commit doesn't leave an untracked reservation.
      existing.maxStorage = newCap
      if (node.appRegistry && typeof node.appRegistry.update === 'function') {
        try { node.appRegistry.update(appKeyHex, { maxStorage: newCap }) } catch (_) {}
      }
      if (typeof node.appRegistry.persistEntry === 'function') {
        try { await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true }) } catch (_) {}
      }
      if (node.storageAdmission.owns(reservation)) node.storageAdmission.commit(reservation)
    } else {
      // No storage admission configured — update the cap directly.
      existing.maxStorage = newCap
      if (node.appRegistry && typeof node.appRegistry.update === 'function') {
        try { node.appRegistry.update(appKeyHex, { maxStorage: newCap }) } catch (_) {}
      }
    }

    this._safeEmit('seed-cap-raised', {
      appKey: appKeyHex,
      oldCap,
      newCap,
      anchored: existing.anchored === true,
      hint: oldCap === null
        ? 'Cap declared for previously-uncapped entry; retriggering replication under new cap.'
        : 'Cap raised; retriggering replication to drain blocks the prior cap blocked.'
    })

    // Already replicating — the entry's updated cap will be picked up on the
    // next repair sweep.
    if (existing._replicating) {
      return { ok: true, changed: true, incrementalBytes, replicationStarted: false }
    }

    const drive = existing.drive
    if (!drive || drive.closed || drive.closing) {
      return { ok: true, changed: true, incrementalBytes, replicationStarted: false }
    }

    existing._replicating = true
    // Fire-and-forget — the caller (seedApp) already has its own replication
    // lifecycle. The meta tags the source for observability.
    this._eagerReplicate(appKeyHex, drive, { ...newOpts, maxStorage: newCap }, { source: 'repin-cap-raised' })
      .finally(() => { existing._replicating = false })

    return { ok: true, changed: true, incrementalBytes, replicationStarted: true }
  }

  /**
   * Read /manifest.json for indexing.
   *
   * With a storage proof, the read is taken from a checkout pinned to the
   * proven drive version and is strictly LOCAL (`wait: false`). Two reasons:
   *
   *  - Honesty: the metadata we index must be the bytes the proof covers. A
   *    live `drive.get()` can resolve against a newer version — or a forked
   *    chain — so the registry would advertise a version nobody proved.
   *  - Leak: the old read raced `drive.get()` against a 5s timer. Losing the
   *    race rejected the caller but left the get outstanding, so a timed-out
   *    manifest lookup kept an in-flight network request alive against a
   *    drive the caller had already given up on.
   *
   * The checkout is always closed, including on the mismatch and error paths.
   * Without a proof this falls back to the legacy timed live read.
   */
  async _readPinnedManifest (drive, proof) {
    if (!proof || typeof drive.checkout !== 'function') {
      return Promise.race([
        drive.get('/manifest.json'),
        new Promise((_resolve, reject) => setTimeout(() => reject(new Error('manifest timeout')), 5000))
      ])
    }

    let checkout = null
    try {
      checkout = drive.checkout(proof.driveVersion)
      if (!checkout) return null
      if (typeof checkout.ready === 'function') await checkout.ready()

      // Fork/length stability: the checkout must be the exact metadata-core
      // state the proof covers. A fork swap between proving and reading would
      // otherwise authorize indexing bytes from a different chain.
      const snapshot = proof.metaCoreSnapshot
      const core = checkout.db && checkout.db.core
      if (snapshot && core) {
        if (Number(core.fork ?? 0) !== Number(snapshot.fork ?? 0) ||
            Number(core.length ?? -1) !== Number(snapshot.length ?? -2)) {
          return null
        }
      }

      return await checkout.get('/manifest.json', { wait: false })
    } finally {
      if (checkout && typeof checkout.close === 'function') {
        try { await checkout.close() } catch (_) {}
      }
    }
  }

  async _verifyReleaseTree (drive, release, proof = null) {
    let snapshot = drive
    let ownsSnapshot = false
    const version = proof?.driveVersion ?? drive?.version
    if (typeof drive?.checkout === 'function' && Number.isSafeInteger(version) && version > 0) {
      snapshot = drive.checkout(version)
      ownsSnapshot = true
    }

    try {
      if (!snapshot || typeof snapshot.get !== 'function' || typeof snapshot.list !== 'function') {
        return { ok: false, error: 'release tree cannot be inspected at the pinned drive version' }
      }
      if (typeof snapshot.ready === 'function') await snapshot.ready()

      const pinnedManifest = await snapshot.get('/manifest.json', { wait: false })
      if (!pinnedManifest) return { ok: false, error: 'release manifest is absent from the pinned drive version' }
      const envelope = JSON.parse(pinnedManifest.toString())?.hiverelay?.release
      if (!envelope || envelope.signature !== release.signature) {
        return { ok: false, error: 'release manifest changed while its content tree was being verified' }
      }

      const files = []
      for await (const entry of snapshot.list('/')) {
        const path = entry?.key
        if (typeof path !== 'string' || path === '/manifest.json' || path === '/.hiverelay/rotation.json') continue
        const content = await snapshot.get(path, { wait: false })
        if (content === null) return { ok: false, error: `release tree file is unavailable: ${path}` }
        files.push({ path, content })
      }
      const actualTreeHash = hashReleaseTree(files)
      if (actualTreeHash !== release.treeHash) {
        return { ok: false, error: 'release treeHash does not match the pinned Hyperdrive contents' }
      }
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err.message || 'release tree verification failed' }
    } finally {
      if (ownsSnapshot && snapshot && typeof snapshot.close === 'function') {
        try { await snapshot.close() } catch (_) {}
      }
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

    try {
      const manifestBuf = await this._readPinnedManifest(drive, proof)
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

      // Signed release metadata is the only authority that can rotate an app
      // onto a new drive without immediately retiring its predecessor. Bind it
      // to the pinned manifest, seed-request publisher, and declared storage
      // bound before persisting any manifest-derived fields.
      const releaseEnvelope = manifest.hiverelay?.release
      let signedRelease = null
      if (releaseEnvelope !== undefined) {
        const verified = verifyAppRelease(releaseEnvelope)
        const releaseContext = {
          appKey: appKeyHex,
          appId,
          version,
          seedPublisher: existing?.publisherPubkey || null,
          maxStorage: existing?.maxStorage || null,
          priorRelease: existing?.release || null
        }
        let contextError = verified.ok
          ? releaseContextError(verified.release, releaseContext)
          : verified.error
        if (verified.ok && !contextError) {
          const treeVerification = await this._verifyReleaseTree(drive, verified.release, proof)
          if (!treeVerification.ok) contextError = treeVerification.error
        }
        if (!verified.ok || contextError) {
          this.emit('app-release-rejected', {
            appId,
            appKey: appKeyHex,
            version,
            reason: contextError || verified.error
          })
          await this.unseedApp(appKeyHex)
          return
        }
        signedRelease = verified.release
      }

      // Scan the actual registry instead of trusting byAppId. seedApp may have
      // already indexed the incoming appId, and byAppId is last-writer-wins;
      // using it here can hide the predecessor we must validate and retain.
      const conflict = contentType === 'app' && appId
        ? findManifestConflict(node.appRegistry, appId, appKeyHex, version, signedRelease)
        : { conflict: false }
      const sameDriveContinuation = Boolean(signedRelease && existing?.release)

      if (signedRelease && conflict.conflict && conflict.shouldReplace) {
        const predecessorPublisher = conflict.existingEntry.publisherPubkey || conflict.existingEntry.release?.publisherPubkey || null
        let transitionError = null
        if (!predecessorPublisher || predecessorPublisher.toLowerCase() !== signedRelease.publisherPubkey) {
          transitionError = 'release publisher does not match predecessor publisher'
        } else if (!sameDriveContinuation && signedRelease.previousDriveKey !== conflict.existingKey) {
          transitionError = 'signed release does not name the current predecessor drive'
        } else if (!sameDriveContinuation && conflict.existingEntry.release) {
          const prior = conflict.existingEntry.release
          if (signedRelease.sequence <= prior.sequence) transitionError = 'rotated release sequence did not advance'
          else if (signedRelease.generation !== prior.generation + 1) transitionError = 'rotated release generation must advance by one'
        }
        if (transitionError) {
          this.emit('app-release-rejected', {
            appId,
            appKey: appKeyHex,
            version,
            reason: transitionError
          })
          await this.unseedApp(appKeyHex)
          return
        }
      }

      // A signed release becomes deletion authority for superseded drives, so
      // capture the pre-index state and persist the accepted envelope before
      // any reclamation can run.
      const previousEntrySnapshot = existing ? { ...existing } : null
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
        publisherPubkey: signedRelease?.publisherPubkey || existing?.publisherPubkey || null,
        release: signedRelease || existing?.release || null
      }, signedRelease ? { persist: false } : {})

      if (signedRelease && typeof node.appRegistry.persistEntry === 'function') {
        try {
          await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
        } catch (err) {
          if (sameDriveContinuation && previousEntrySnapshot) {
            node.appRegistry.set(appKeyHex, previousEntrySnapshot, { persist: false })
          }
          this.emit('app-release-rejected', {
            appId,
            appKey: appKeyHex,
            version,
            reason: 'release registry persistence failed: ' + (err.message || String(err))
          })
          if (!sameDriveContinuation) await this.unseedApp(appKeyHex)
          return
        }
      }

      if (contentType !== 'app') return
      if (!appId) return

      // Check for version conflicts with existing apps. Legacy unsigned
      // releases preserve the old immediate-replacement behavior. A verified
      // signed transition retains exactly the publisher-declared rollback set
      // and asks the existing safe purge path to reclaim only older drives.
      if (conflict.conflict) {
        if (conflict.shouldReplace) {
          this.emit('app-replaced', {
            appId,
            oldKey: conflict.existingKey,
            oldVersion: conflict.existingVersion,
            newKey: appKeyHex,
            newVersion: version,
            signedRotation: Boolean(signedRelease && !sameDriveContinuation)
          })
          if (signedRelease) {
            await this._reclaimReleaseRollback({
              appId,
              publisherPubkey: signedRelease.publisherPubkey,
              retainKeys: signedRelease.rollbackDriveKeys
            })
          } else {
            await this.unseedApp(conflict.existingKey)
          }
        } else {
          const currentRelease = conflict.existingEntry.release
          const rollbackProtected = currentRelease &&
            currentRelease.publisherPubkey === (signedRelease?.publisherPubkey || existing?.publisherPubkey) &&
            Array.isArray(currentRelease.rollbackDriveKeys) &&
            currentRelease.rollbackDriveKeys.includes(appKeyHex)
          if (rollbackProtected) {
            // A retained predecessor can receive its signed rotation pointer
            // after the successor is indexed. Re-indexing its older manifest
            // must not accidentally unseed the rollback copy. AppRegistry's
            // update above is last-writer-wins, so restore the canonical hint
            // to the newer drive as well (catalog remains version/sequence
            // ordered independently).
            if (node.appRegistry.byAppId) node.appRegistry.byAppId.set(appId, conflict.existingKey)
            return
          }
          this.emit('app-version-rejected', {
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
    // Repair pulls blocks and re-anchors — both storage-producing. Under a
    // read-only physical authority the relay may still SERVE what it holds,
    // but it must not grow. Stop before drive.update()/download().
    if (!this._durableWritesAvailable()) return false
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
      this.emit('repair-update-failed', { appKey: appKeyHex, error: err.message })
      return false
    }

    if ((scope && scope.aborted) || drive.closed || drive.closing || drive.version === 0) {
      // Still no version — no peer has data for this drive yet
      if (typeof node.appRegistry.recordAnchorCheck === 'function') {
        node.appRegistry.recordAnchorCheck(appKeyHex)
      }
      return false
    }

    // Bind repair to one signed metadata/blob snapshot before opening any
    // storage-producing range. This keeps repair from racing eager replication
    // and publishing the retired metadata-only `anchored=true` state.
    let sizeProof = null
    try {
      sizeProof = await raceOr(getDriveSize(drive, {
        timeoutMs: 10_000,
        requireAuthoritative: true,
        pinSnapshots: true
      }))
      if (!Number.isSafeInteger(sizeProof.totalBytes) || sizeProof.totalBytes < 0 ||
          sizeProof.totalBytes > cap) {
        this.emit('seed-aborted', {
          appKey: appKeyHex,
          reason: 'maxStorage-too-small',
          driveBytes: sizeProof.totalBytes,
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
        this.emit('anchored', { appKey: appKeyHex, version: sizeProof.driveVersion, source: 'repair' })
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
      this.emit('repair-download-failed', { appKey: appKeyHex, error: err.message })
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
    if (!this._durableWritesAvailable()) return { checked: 0, repaired: 0, stillUnanchored: 0 }
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
          this.emit('repair-error', { appKey, error: err.message })
        }
      }
    })())
    await Promise.all(workers)

    const stillUnanchored = checked - repaired
    return { checked, repaired, stillUnanchored }
  }

  async _drainAuxShareBundleResources (appKeyHex) {
    if (this._auxShareBundleResources.size === 0) return
    const pending = []
    for (const res of this._auxShareBundleResources) {
      if (appKeyHex && res.appKey !== appKeyHex) continue
      // Wait for the full operation (update + snapshot + read) to settle, not
      // just the download tracker — the fetch may be blocked in core.update().
      if (res.operationSettled) pending.push(res.operationSettled.catch(() => {}))
    }
    if (pending.length > 0) await Promise.allSettled(pending)
  }

  /**
   * Ordered, retry-safe teardown of one auxiliary share-bundle resource.
   *
   * Order matters and is the inverse of acquisition: stop new replication
   * (listener) → stop discovery → stop the download tracker → close the
   * snapshot session → close the core → close a store we own. Closing the
   * core before its snapshot session, or the store before its cores, throws
   * SESSION_CLOSED / "Mutex has been destroyed" out of teardown.
   *
   * Each step records its own settled flag, so a step that rejects leaves
   * every DOWNSTREAM owner untouched and the resource parked in
   * _auxShareBundleResources for a retry — the same ownership discipline
   * unseedApp uses for drive retirement. The error propagates; callers that
   * must not fail (best-effort cleanup) catch it themselves.
   */
  async _releaseAuxShareBundleResource (resource) {
    if (!resource) return
    const node = this.node || {}

    if (!resource.listenerSettled) {
      const swarm = node.swarm
      if (resource.onConnection && swarm && typeof swarm.removeListener === 'function') {
        swarm.removeListener('connection', resource.onConnection)
      }
      resource.listenerSettled = true
    }

    if (!resource.discoverySettled) {
      if (resource.discovery && typeof resource.discovery.destroy === 'function') {
        await resource.discovery.destroy()
      } else if (resource.core && node.swarm && typeof node.swarm.leave === 'function') {
        await node.swarm.leave(resource.core.discoveryKey)
      }
      resource.discoverySettled = true
    }

    if (!resource.trackerSettled) {
      if (resource.tracker && typeof resource.tracker.destroy === 'function') {
        resource.tracker.destroy()
      }
      resource.trackerSettled = true
    }

    if (!resource.snapshotSettled) {
      if (resource.snapshotCore && typeof resource.snapshotCore.close === 'function') {
        await resource.snapshotCore.close()
      }
      resource.snapshotSettled = true
    }

    if (!resource.coreSettled) {
      if (resource.core && typeof resource.core.close === 'function') {
        await resource.core.close()
      }
      resource.coreSettled = true
    }

    if (!resource.storeSettled) {
      // Only close a store this read OWNS. When _readShareBundle falls back to
      // node.store the corestore belongs to the node — closing it here would
      // tear down every drive on the relay.
      if (resource.auxStore && resource.auxStore !== node.store &&
          typeof resource.auxStore.close === 'function') {
        await resource.auxStore.close()
      }
      resource.storeSettled = true
    }

    this._auxShareBundleResources.delete(resource)
  }

  async _readShareBundle (shareBundleKey, opts = {}) {
    const node = this.node
    const appKey = isValidHexKey(opts.appKey, 64) ? opts.appKey.toLowerCase() : null
    if (!isValidHexKey(shareBundleKey, 64) || !appKey || !node.swarm) return null
    // Storage admission gate: the aux read must be admitted before any core
    // materializes on disk.
    if (node.storageAdmission && typeof node.storageAdmission.mutationAdmission === 'function') {
      if (!node.storageAdmission.mutationAdmission().allowed) return null
    }
    if (node.storageAdmission && typeof node.storageAdmission.canAcknowledge === 'function') {
      if (!node.storageAdmission.canAcknowledge(`drive:${appKey}`)) return null
    }
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 30_000
    let core = null
    let auxStore = null
    let discovery = null
    let onConnection = null
    let ownedResource = null
    try {
      if (typeof opts.createAuxStore === 'function') {
        auxStore = await opts.createAuxStore()
      } else if (node.store && typeof node.store.get === 'function') {
        auxStore = node.store
      } else {
        return null
      }
      if (!auxStore || typeof auxStore.get !== 'function') return null
      if (typeof auxStore.ready === 'function') await auxStore.ready()
      onConnection = (conn) => {
        try { auxStore.replicate(conn) } catch (_) {}
      }
      if (typeof node.swarm.on === 'function') node.swarm.on('connection', onConnection)
      // Exactly one core session + one topic join per read. This block was
      // duplicated verbatim by the da70b0f restore: the second acquisition
      // overwrote `core`/`discovery` with the first pair still open, so every
      // read leaked one core session and one PeerDiscovery join (neither is
      // reachable from the teardown resource, which only ever saw the second
      // pair) and paid the flush race twice.
      core = auxStore.get({ key: b4a.from(shareBundleKey, 'hex') })
      await core.ready()
      discovery = node.swarm.join(core.discoveryKey, { server: false, client: true })
      if (discovery && typeof discovery.flushed === 'function') {
        await Promise.race([
          discovery.flushed().catch(() => {}),
          new Promise(resolve => { const tmr = setTimeout(resolve, Math.min(timeoutMs, 5_000)); if (typeof tmr.unref === 'function') tmr.unref() })
        ])
      }
      // Reject oversized proofs BEFORE downloading any body range.
      const byteLength = Number(core.byteLength)
      if (Number.isSafeInteger(byteLength) && byteLength > STORAGE_SHARE_BUNDLE_MAX_BYTES) {
        return null
      }
      // Register the active resource early so a concurrent unseedApp drains
      // this fetch before releasing drive debt — even while update() is in
      // flight.
      let resolveSettled
      const operationSettled = new Promise(resolve => { resolveSettled = resolve })
      ownedResource = { appKey, core, snapshotCore: null, tracker: null, auxStore, discovery, onConnection, operationSettled }
      this._auxShareBundleResources.add(ownedResource)
      try {
        if (typeof core.update === 'function') {
          try { await core.update({ wait: true }) } catch (_) {}
        }
        const byteLengthAfter = Number(core.byteLength)
        if (Number.isSafeInteger(byteLengthAfter) && byteLengthAfter > STORAGE_SHARE_BUNDLE_MAX_BYTES) {
          return null
        }
        // Snapshot-based read: if the core supports snapshots, read block 0
        // from a wait:false snapshot. A fork swap between the proof and the
        // snapshot cannot authorize a body read.
        let readCore = core
        if (typeof core.snapshot === 'function') {
          const snapshotCore = core.snapshot({ wait: false })
          ownedResource.snapshotCore = snapshotCore
          if (typeof snapshotCore.ready === 'function') await snapshotCore.ready()
          // Fork stability: the snapshot must match the core's fork, otherwise
          // a fork swap between proof and snapshot could authorize a body read
          // from a different chain.
          const coreFork = Number(core.fork ?? 0)
          const snapshotFork = Number(snapshotCore.fork ?? 0)
          if (coreFork !== snapshotFork) return null
          const pinnedByteLength = Number(snapshotCore.byteLength)
          if (Number.isSafeInteger(pinnedByteLength) && pinnedByteLength > STORAGE_SHARE_BUNDLE_MAX_BYTES) {
            return null
          }
          readCore = snapshotCore
          const tracker = readCore.download ? readCore.download({ start: 0, end: 1 }) : null
          ownedResource.tracker = tracker
          if (tracker && typeof tracker.done === 'function') {
            await Promise.race([
              tracker.done(),
              new Promise((_resolve, reject) => { const tmr = setTimeout(() => reject(new Error('share bundle range timeout')), timeoutMs); if (typeof tmr.unref === 'function') tmr.unref() })
            ])
          }
        }
        const block = await readCore.get(0, { wait: false, timeout: timeoutMs })
        if (!block) return null
        if (Number.isSafeInteger(block.byteLength) && block.byteLength > STORAGE_SHARE_BUNDLE_MAX_BYTES) return null
        const parsed = JSON.parse(b4a.toString(block))
        return parsed && typeof parsed === 'object' ? parsed : null
      } finally {
        this._auxShareBundleResources.delete(ownedResource)
        resolveSettled()
      }
    } catch (_) {
      return null
    } finally {
      // Single ordered teardown. Previously this block open-coded the release
      // and did NOT close the snapshot session or destroy the download
      // tracker — _releaseAuxShareBundleResource was the only code that did,
      // and nothing called it. Every snapshot-path share-bundle read therefore
      // leaked a core session and a download tracker.
      //
      // The synthetic fallback covers the early `return null` paths that bail
      // before the tracked resource exists but after cores/discovery are open.
      const resource = ownedResource ||
        { appKey, core, snapshotCore: null, tracker: null, auxStore, discovery, onConnection }
      try { await this._releaseAuxShareBundleResource(resource) } catch (_) {}
    }
  }

  /**
   * An already-seeded drive never re-enters the async anchor path. A custody
   * re-pin still has to verify and record its share receipt, otherwise the
   * dealer waits forever for a quorum that this relay silently ignored.
   * Keep this asynchronous to match fresh-seed behaviour: /seed acknowledges
   * durable drive ownership while the publisher polls the receipt registry.
   */
  _recordCustodyReceiptOnRepin (appKeyHex, existing, opts) {
    if (!opts || opts.blind !== true || !opts.custodyIntentId) return

    const version = Number.isFinite(opts.contentVersion)
      ? opts.contentVersion
      : (existing && Number.isFinite(existing.version) ? existing.version : 0)
    const promise = this._recordCustodyReceipt(appKeyHex, opts, version)
      .catch((err) => {
        this._safeEmit('custody-receipt-error', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          error: (err && err.message) || String(err)
        })
        return null
      })

    const scope = this.node && this.node._scope
    if (scope && typeof scope.tracked === 'function') scope.tracked(promise)
  }

  async _recordCustodyReceipt (appKeyHex, opts = {}, contentVersion = 0) {
    const node = this.node
    if (!opts.blind || !opts.custodyIntentId || !node.seedingRegistry || !node.swarm?.keyPair) return null

    // PVSS share custody (v2). If the bound intent declares a share scheme,
    // this relay must PUBLICLY verify the encrypted share it was assigned —
    // no secret key — before anchoring a receipt. SD2: a failed (or
    // unavailable) verification must NOT anchor; emit
    // `custody:share-verify-failed` and skip the receipt.
    let pvssFields = null
    let intent = null
    try {
      intent = typeof node.seedingRegistry.getCustodyIntent === 'function'
        ? node.seedingRegistry.getCustodyIntent(opts.custodyIntentId)
        : null
    } catch (_) { intent = null }

    const wantsPvss = !!(intent && intent.shareScheme) || !!opts.shareScheme
    if (wantsPvss) {
      if (!intent || !intent.shareScheme) {
        this._safeEmit('custody:share-verify-failed', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          shareBundleKey: null,
          reason: 'intent-unavailable'
        })
        return null
      }
      const relayPubkey = b4a.toString(node.swarm.keyPair.publicKey, 'hex')
      const bundle = typeof this._readShareBundle === 'function'
        ? await this._readShareBundle(intent.shareBundleKey, { appKey: appKeyHex })
        : null
      const result = verifyShareBundleForRelay(intent, bundle, relayPubkey)
      if (!result.ok) {
        this._safeEmit('custody:share-verify-failed', {
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
      this._safeEmit('custody-receipt', { appKey: appKeyHex, intentId: opts.custodyIntentId, receipt })
      return receipt
    } catch (err) {
      this._safeEmit('custody-receipt-error', {
        appKey: appKeyHex,
        intentId: opts.custodyIntentId,
        error: err.message || String(err)
      })
      return null
    }
  }

  async unseedApp (appKeyHex, opts = {}) {
    const node = this.node
    let owner = this._retiringDrives.get(appKeyHex)

    if (!owner) {
      const entry = node.appRegistry.get(appKeyHex)
      if (!entry) return
      // A forget retirement ENDS in a durable delete, and that delete hits
      // memory first. If the durable write then fails we restore the entry —
      // but the restore is itself a registry write, so under an unavailable
      // physical authority it fails too and the drive vanishes from the
      // registry entirely. Refuse before the first mutation instead of
      // discovering it half-way through teardown.
      if (opts.forget !== false && typeof node.appRegistry.assertDurableWritesAvailable === 'function') {
        node.appRegistry.assertDurableWritesAvailable()
      }
      entry.retiring = true
      owner = {
        appKey: appKeyHex,
        entry,
        forget: opts.forget !== false,
        bridgeRegistered: !!node.distributedDriveBridge,
        rangesSettled: false,
        snapshotCoresSettled: false,
        discoverySettled: false,
        driveSettled: false,
        commitmentReleased: false,
        completed: false,
        inflight: null
      }
      this._retiringDrives.set(appKeyHex, owner)
    } else {
      if (opts.forget !== undefined) owner.forget = opts.forget !== false
    }

    // Coalesce concurrent retirements of the same drive onto ONE owner. A
    // second caller (e.g. an eviction upgrading a shutdown to a forget) must
    // not re-close resources the first caller already has in flight — it
    // chains behind it instead. Its intent is applied above, so a forget
    // arriving mid-shutdown is still honoured by the in-flight pass.
    const previous = owner.inflight || Promise.resolve()
    const run = previous.catch(() => {})
      .then(() => this._withDriveLease(appKeyHex, () => this._retireDrive(owner), { allowWhenStopping: true }))
    owner.inflight = run.catch(() => {})
    return run
  }

  /**
   * Idempotent drive retirement. Every step records a settled flag on the
   * owner, so a rejection parks the owner in _retiringDrives with all
   * DOWNSTREAM owners intact and a retry resumes exactly where it stopped.
   */
  async _retireDrive (owner) {
    if (owner.completed) return
    const node = this.node
    const appKeyHex = owner.appKey

    // Phase 1: Settle live resources, inverse of acquisition — stop pulling
    // bytes (ranges → proof snapshots), stop being findable (discovery),
    // stop bridging, then close the drive. Ordered so the durable delete
    // (Phase 2) cannot race with in-flight replication or bridge lookups.
    // A step that throws leaves everything after it untouched for the retry.
    if (!owner.rangesSettled) {
      const ranges = owner.entry.downloadRanges
      if (Array.isArray(ranges)) {
        while (ranges.length > 0) {
          const dl = ranges[0]
          if (dl && typeof dl.destroy === 'function') dl.destroy()
          ranges.shift()
        }
        owner.entry.downloadRanges = null
      }
      owner.rangesSettled = true
    }

    if (!owner.snapshotCoresSettled) {
      const cores = owner.entry.downloadSnapshotCores
      if (Array.isArray(cores)) {
        while (cores.length > 0) {
          const core = cores[0]
          if (core && typeof core.close === 'function') await core.close()
          cores.shift()
        }
        owner.entry.downloadSnapshotCores = null
      }
      owner.snapshotCoresSettled = true
    }

    // Destroy the exact PeerDiscovery handles this drive owns, rather than
    // leaving the topic by key: swarm.leave(discoveryKey) cannot distinguish
    // this drive's join from another subsystem's join on the same topic. A
    // handle that fails to destroy is retained by identity for the retry.
    if (!owner.discoverySettled) {
      const handles = owner.entry.discoveryHandles
      if (handles && typeof handles.delete === 'function') {
        for (const handle of [...handles]) {
          if (handle && typeof handle.destroy === 'function') await handle.destroy()
          handles.delete(handle)
        }
        owner.entry.discoveryHandles = null
      }
      owner.discoverySettled = true
    }

    if (owner.bridgeRegistered && node.distributedDriveBridge) {
      node.distributedDriveBridge.unregisterDrive(appKeyHex)
      owner.bridgeRegistered = false
    }

    if (!owner.driveSettled) {
      if (owner.entry.drive && typeof owner.entry.drive.close === 'function') {
        await owner.entry.drive.close()
        owner.entry.drive = null
      }
      owner.driveSettled = true
    }

    // Drain any active auxiliary share-bundle fetches for this app before
    // the durable delete — a concurrent fetch must not race with teardown.
    await this._drainAuxShareBundleResources(appKeyHex)

    // Phase 2: Durable delete. The live resources are already settled, so a
    // failure here leaves the entry restored in the registry and parked in
    // _retiringDrives for retry. Swarm leave is deferred to Phase 3 so a
    // failed retirement retains the topic for the retry attempt.
    if (owner.forget && !owner.durableDeleted) {
      node.appRegistry.delete(appKeyHex, { persist: false })
      try {
        if (typeof node.appRegistry.persistDelete === 'function') {
          await node.appRegistry.persistDelete(appKeyHex, { throwOnError: true })
        }
        owner.durableDeleted = true
      } catch (err) {
        // Restore the entry so a retry finds it; keep it in _retiringDrives.
        if (!node.appRegistry.has(appKeyHex)) {
          node.appRegistry.set(appKeyHex, owner.entry, { persist: false })
        }
        throw err
      }
    }

    // Phase 3: Complete — the durable delete succeeded, so leave the swarm
    // and release the storage admission commitment.
    try { if (node.swarm && typeof node.swarm.leave === 'function') await node.swarm.leave(owner.entry.discoveryKey) } catch (_) {}
    if (owner.forget && !owner.commitmentReleased &&
        node.storageAdmission && typeof node.storageAdmission.release === 'function') {
      try { node.storageAdmission.release(`drive:${appKeyHex}`) } catch (_) {}
      owner.commitmentReleased = true
    }

    owner.completed = true
    owner.entry.retiring = false
    this._retiringDrives.delete(appKeyHex)
    this._safeEmit('unseeded', { appKey: appKeyHex })
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
    if (!tracked && node.storageAdmission && typeof node.storageAdmission.runKeyMutation === 'function') {
      return node.storageAdmission.runKeyMutation(`drive:${appKeyHex}`, () =>
        this._registerPersistentDownloads(appKeyHex, drive, true))
    }
    const entry = node.appRegistry && node.appRegistry.get(appKeyHex)
    if (!entry) return
    if (!drive || drive.closed || drive.closing) return
    const cap = positiveStorageBound(entry.maxStorage)
    if (cap === null) return

    // A live `end: -1` range keeps expanding as metadata advances and can
    // materialize bytes that were never measured or admitted. Prove one
    // immutable metadata/blob snapshot, ensure its aggregate footprint fits
    // the durable cap, then register only those finite ranges.
    let settleRegistration = null
    const token = {
      settled: new Promise(resolve => { settleRegistration = resolve })
    }
    entry.downloadRegistration = token
    let proof = null
    try {
      proof = await getDriveSize(drive, {
        timeoutMs: 10_000,
        requireAuthoritative: true,
        pinSnapshots: true
      })
      if (node.appRegistry.get(appKeyHex) !== entry || entry.drive !== drive ||
          entry.downloadRegistration !== token || drive.closed || drive.closing) return
      if (!Number.isSafeInteger(proof && proof.totalBytes) || proof.totalBytes < 0 || proof.totalBytes > cap) {
        this._safeEmit('persistent-download-error', {
          appKey: appKeyHex,
          error: 'drive footprint exceeds durable maxStorage bound'
        })
        return
      }
      await this._installPersistentDownloadProof(appKeyHex, drive, proof)
    } finally {
      try {
        await this._closeDriveProof(proof)
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
    // Be total: malformed inputs are MALFORMED_REQUEST, never a throw or a
    // misleading domain error. Validate types and shapes before any lookup so
    // a bad request cannot surface internal state (e.g. APP_NOT_FOUND for a
    // non-string key that was never going to match).
    if (typeof appKeyHex !== 'string' || appKeyHex.length !== 64 || !/^[0-9a-f]+$/i.test(appKeyHex) ||
        typeof publisherPubkeyHex !== 'string' || publisherPubkeyHex.length !== 64 || !/^[0-9a-f]+$/i.test(publisherPubkeyHex) ||
        typeof signatureHex !== 'string' || signatureHex.length === 0 ||
        !Number.isSafeInteger(timestamp) || timestamp < 0) {
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
    if (!sigBuf || sigBuf.length < sodium.crypto_sign_BYTES ||
        !pubkeyBuf || pubkeyBuf.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
      return { ok: false, error: 'MALFORMED_REQUEST' }
    }

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
