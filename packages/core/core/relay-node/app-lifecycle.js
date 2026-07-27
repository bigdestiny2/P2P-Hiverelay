import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { updateWithTimeout, downloadWithTimeout, getDriveSize } from './cancellable-drive-update.js'
import { isAbortError } from './lifecycle-scope.js'
import { verifyShareBundleForRelay } from '../pvss.js'
import { STORAGE_SHARE_BUNDLE_MAX_BYTES } from '../../config/storage-admission-authority.js'
import { positiveStorageBound } from '../../config/storage-cap.js'
import {
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'

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
    // Drives whose live resources (ranges, drive, bridge) have been settled
    // but whose durable delete has not yet completed. On failure the entry is
    // restored to the registry and parked here so a retry can finish the
    // retirement without re-closing already-settled resources.
    this._retiringDrives = new Map()
    // Active auxiliary share-bundle fetches. unseedApp drains these before
    // releasing drive debt so a concurrent fetch cannot race with teardown.
    this._auxShareBundleResources = new Set()
  }

  /**
   * The seededApps Map. Delegates to the AppRegistry so existing external
   * callers that reach into node.seededApps keep seeing the same instance.
   */
  get seededApps () {
    return this.node.appRegistry.apps
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
    if (!node.seeder) throw new Error('Seeding not enabled')
    if (!isValidHexKey(appKeyHex)) throw new Error('Invalid app key: must be 64 hex characters')

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
    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
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
        return { discoveryKey: dkHex, alreadySeeded: true }
      }
      // else: placeholder entry from load() — fall through to seed properly.
    }

    // Acquire seed mutex to prevent concurrent eviction races
    while (this._seedMutex) {
      await new Promise(resolve => setTimeout(resolve, 50))
    }
    this._seedMutex = true
    try {
      return await this._seedAppInner(appKeyHex, normalizedOpts, contentType, parentKey, mountPath, privacyTier)
    } finally {
      this._seedMutex = false
    }
  }

  async _seedAppInner (appKeyHex, opts, contentType, parentKey, mountPath, privacyTier) {
    const node = this.node

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
    if (node.storageAdmission && typeof node.storageAdmission.reserve === 'function' && admissionCap !== null) {
      const reservation = node.storageAdmission.reserve(`drive:${appKeyHex}`, admissionCap)
      if (!reservation || reservation.allowed !== true) {
        const err = new Error('Storage admission blocked: ' + (reservation && reservation.reason))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
      // Commit on successful seed (after drive creation); for now track it.
      this._pendingAdmission = reservation
    }

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
    const drive = new Hyperdrive(node.store.session(), appKey)

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
          new Promise((_, reject) => {
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
      node.swarm.join(discoveryKey, { server: true, client: true })
      node.swarm.flush().then(() => { if (done) done() }).catch(() => { if (done) done() })

      // Eagerly replicate drive content. Extracted to a method in v0.8.12
      // so the alreadySeeded re-pin path can call it too — see
      // _reconcileSeedOptsOnRepin.
      //
      // Tracked in the LifecycleScope so stop() drains the loop before
      // tearing down the corestore (vector A1 in STALE-REF-INVENTORY.md).
      this._trackEagerReplicate(appKeyHex, drive, opts, { source: 'fresh-seed' })

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

      node.appRegistry.set(appKeyHex, {
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
        maxStorage
      })

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
      this._registerPersistentDownloads(appKeyHex, drive).catch((err) => {
        this.emit('persistent-download-error', {
          appKey: appKeyHex,
          error: err.message || String(err)
        })
      })

      if (node.distributedDriveBridge) {
        node.distributedDriveBridge.registerDrive(appKeyHex, drive)
      }

      this.emit('seeding', { appKey: appKeyHex, discoveryKey: b4a.toString(discoveryKey, 'hex') })
      return { discoveryKey: b4a.toString(discoveryKey, 'hex') }
    } catch (err) {
      try { await drive.close() } catch (_) {}
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

      try {
        node.swarm.join(discoveryKey, { server: true, client: true })
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
          const cap = Number.isFinite(opts.maxStorage) && opts.maxStorage > 0
            ? opts.maxStorage
            : null
          if (cap !== null) {
            const { totalBytes, metaBytes, blobBytes } = await raceOr(
              getDriveSize(drive, { timeoutMs: 10_000 })
            )
            if (totalBytes > cap) {
              const recommendedCap = Math.ceil(totalBytes * 1.25)
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
            await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: 120_000 }))
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
          const fullyReplicated = downloadComplete && await this._isDriveFullyReplicated(drive)
          if (fullyReplicated && node.appRegistry && typeof node.appRegistry.setAnchored === 'function') {
            node.appRegistry.setAnchored(appKeyHex, drive.version)
            await this._recordCustodyReceipt(appKeyHex, opts, drive.version)
            this.emit('anchored', { appKey: appKeyHex, version: drive.version, source })
            this.emit('reseeded', { appKey: appKeyHex, version: drive.version, source })
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
        ok: true, changed: false,
        reason: newCap === null ? 'cap-omitted-on-recovery' : 'cap-unchanged',
        oldCap, newCap, effectiveCap: oldCap
      }
    }

    if (oldCap !== null && newCap < oldCap) {
      const warning = {
        appKey: appKeyHex, reason: 'cap-lowered-on-repin', oldCap, newCap,
        hint: 'Lowering maxStorage on a recovered entry is not honored; relay keeps the higher persisted cap.'
      }
      this._safeEmit('seed-cap-warning', warning)
      return { ok: true, changed: false, effectiveCap: oldCap, ...warning }
    }

    if (oldCap === null) {
      const warning = {
        appKey: appKeyHex, reason: 'cap-baseline-unknown-on-repin', oldCap, newCap,
        incrementalBytes: null, effectiveCap: oldCap,
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
   * Read manifest.json from a drive and deduplicate by appId.
   * If an older version of the same app is already seeded, unseed it.
   */
  async _indexAppManifest (appKeyHex, drive) {
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
      const manifestBuf = await Promise.race([
        drive.get('/manifest.json'),
        new Promise((_resolve, reject) => setTimeout(() => reject(new Error('manifest timeout')), 5000))
      ])
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
        categories: manifest.categories || null
      })

      if (contentType !== 'app') return
      if (!appId) return

      // Check for version conflicts with existing apps
      const conflict = node.appRegistry.checkConflict(appId, appKeyHex, version)
      if (conflict.conflict) {
        if (conflict.shouldReplace) {
          this.emit('app-replaced', {
            appId,
            oldKey: conflict.existingKey,
            oldVersion: conflict.existingVersion,
            newKey: appKeyHex,
            newVersion: version
          })
          await this.unseedApp(conflict.existingKey)
        } else {
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
    const entry = node.appRegistry.get(appKeyHex)
    if (!entry || !entry.drive) return false
    if (entry.anchored === true) return true // already anchored, nothing to do

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
      node.swarm.join(drive.discoveryKey, { server: true, client: true })
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
        await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: downloadTimeout }))
      } catch (err) {
        if (isAbortError(err)) return false
        downloadComplete = false
      }

      if ((scope && scope.aborted) || drive.closed || drive.closing) return false

      if (drive.version > 0 && downloadComplete && await this._isDriveFullyReplicated(drive)) {
        node.appRegistry.setAnchored(appKeyHex, drive.version)
        await this._recordCustodyReceipt(appKeyHex, entry, drive.version)
        this.emit('anchored', { appKey: appKeyHex, version: drive.version, source: 'repair' })
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

  async _releaseAuxShareBundleResource (resource) {
    if (!resource) return
    this._auxShareBundleResources.delete(resource)
    try { if (resource.tracker && typeof resource.tracker.destroy === 'function') resource.tracker.destroy() } catch (_) {}
    try { if (resource.snapshotCore && typeof resource.snapshotCore.close === 'function') await resource.snapshotCore.close() } catch (_) {}
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
      core = auxStore.get({ key: b4a.from(shareBundleKey, 'hex') })
      await core.ready()
      discovery = node.swarm.join(core.discoveryKey, { server: false, client: true })
      if (discovery && typeof discovery.flushed === 'function') {
        await Promise.race([
          discovery.flushed().catch(() => {}),
          new Promise(resolve => { const tmr = setTimeout(resolve, Math.min(timeoutMs, 5_000)); if (typeof tmr.unref === 'function') tmr.unref() })
        ])
      }
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
      const ownedResource = { appKey, core, snapshotCore: null, tracker: null, auxStore, discovery, onConnection, operationSettled }
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
              new Promise((_, reject) => { const tmr = setTimeout(() => reject(new Error('share bundle range timeout')), timeoutMs); if (typeof tmr.unref === 'function') tmr.unref() })
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
      if (onConnection && typeof node.swarm.removeListener === 'function') {
        try { node.swarm.removeListener('connection', onConnection) } catch (_) {}
      }
      if (discovery && typeof discovery.destroy === 'function') {
        try { await discovery.destroy() } catch (_) {}
      } else if (core) {
        try { await node.swarm.leave(core.discoveryKey) } catch (_) {}
      }
      if (core) {
        try { await core.close() } catch (_) {}
      }
      if (auxStore && auxStore !== node.store && typeof auxStore.close === 'function') {
        try { await auxStore.close() } catch (_) {}
      }
    }
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
        ? await this._readShareBundle(intent.shareBundleKey)
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
      entry.retiring = true
      owner = {
        appKey: appKeyHex,
        entry,
        forget: opts.forget !== false,
        bridgeRegistered: !!node.distributedDriveBridge,
        rangesSettled: false,
        driveSettled: false
      }
      this._retiringDrives.set(appKeyHex, owner)
    } else {
      if (opts.forget !== undefined) owner.forget = opts.forget !== false
    }

    // Phase 1: Settle live resources (download ranges → bridge → drive).
    // Ordered so the durable delete (Phase 2) cannot race with in-flight
    // replication or bridge lookups. Only runs once — on retry these are
    // already null.
    if (!owner.rangesSettled) {
      if (Array.isArray(owner.entry.downloadRanges)) {
        for (const dl of owner.entry.downloadRanges) {
          try { if (dl && typeof dl.destroy === 'function') dl.destroy() } catch (_) {}
        }
        owner.entry.downloadRanges = null
      }
      owner.rangesSettled = true
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
    if (owner.forget && node.storageAdmission && typeof node.storageAdmission.release === 'function') {
      try { node.storageAdmission.release(`drive:${appKeyHex}`) } catch (_) {}
    }

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
  async _registerPersistentDownloads (appKeyHex, drive) {
    const node = this.node
    const entry = node.appRegistry && node.appRegistry.get(appKeyHex)
    if (!entry) return
    if (!drive || drive.closed || drive.closing) return

    // Replace any prior ranges (idempotent — see retry path above).
    if (Array.isArray(entry.downloadRanges)) {
      for (const dl of entry.downloadRanges) {
        try { if (dl && typeof dl.destroy === 'function') dl.destroy() } catch (_) {}
      }
    }
    entry.downloadRanges = []

    // Metadata core — always present after drive.ready().
    if (drive.db && drive.db.core && typeof drive.db.core.download === 'function') {
      try {
        const metaDl = drive.db.core.download({ start: 0, end: -1 })
        entry.downloadRanges.push(metaDl)
      } catch (_) { /* core may already be closing — skip */ }
    }

    // Blob core — lazy. getBlobs() lazily creates / opens it. May fail
    // if the drive is mid-close; that's fine, skip + retry next cycle.
    let blobs = drive.blobs
    if (!blobs && typeof drive.getBlobs === 'function') {
      blobs = await drive.getBlobs().catch(() => null)
    }
    if (blobs && blobs.core && typeof blobs.core.download === 'function') {
      try {
        const blobDl = blobs.core.download({ start: 0, end: -1 })
        entry.downloadRanges.push(blobDl)
      } catch (_) { /* skip */ }
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
