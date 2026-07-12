import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { updateWithTimeout, downloadWithTimeout, getDriveSize } from './cancellable-drive-update.js'
import { isAbortError } from './lifecycle-scope.js'
import { verifyShareBundleForRelay } from '../pvss.js'
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
  }

  /**
   * The seededApps Map. Delegates to the AppRegistry so existing external
   * callers that reach into node.seededApps keep seeing the same instance.
   */
  get seededApps () {
    return this.node.appRegistry.apps
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
    if (!entries.length) {
      await this.migrateOldSeededApps()
      return []
    }
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
          // Preserve the paid-lease marker across restart so retainUntil stays
          // an enforced lease (sweep acts on it; eviction protects it).
          leaseManaged: entry.leaseManaged === true
        })
        this.emit('reseeded', { appKey: entry.appKey })
      } catch (err) {
        this.emit('reseed-error', { appKey: entry.appKey, error: err })
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
        this._reconcileSeedOptsOnRepin(appKeyHex, existing, normalizedOpts)
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, normalizedOpts)
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
    const recoveringExisting = this.seededApps.has(appKeyHex)

    // Re-check after acquiring mutex — another call may have seeded it.
    // Same null-discoveryKey guard + v0.8.12 opts reconcile as the
    // pre-mutex check in seedApp().
    if (this.seededApps.has(appKeyHex)) {
      const existing = this.seededApps.get(appKeyHex)
      if (existing && existing.discoveryKey) {
        const dkHex = typeof existing.discoveryKey === 'string'
          ? existing.discoveryKey
          : b4a.toString(existing.discoveryKey, 'hex')
        this._reconcileSeedOptsOnRepin(appKeyHex, existing, opts)
        this._recordCustodyReceiptOnRepin(appKeyHex, existing, opts)
        return { discoveryKey: dkHex, alreadySeeded: true }
      }
      // else: placeholder entry from load() — fall through.
    }

    // Existing registry entries may be reopened while over cap so the node can
    // boot, serve, inspect and manually unseed them. Every genuinely NEW pin
    // must pass the logical-cap + physical-reserve gate. This never turns on
    // eviction; shedding remains an explicit operator policy.
    if (!recoveringExisting) {
      const requestedBytes = Number.isSafeInteger(opts.maxStorage) && opts.maxStorage > 0
        ? opts.maxStorage
        : 0
      const admission = typeof node._storageAdmission === 'function'
        ? node._storageAdmission(requestedBytes)
        : {
            allowed: (Number(node.config.maxStorageBytes) - Number(node.seeder.totalBytesStored || 0)) > requestedBytes,
            reason: 'storage-cap-reached'
          }
      if (!admission.allowed) {
        const err = new Error('Storage admission blocked: ' + (admission.reason || 'insufficient-storage'))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = admission
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

      const registrySnapshot = typeof node.appRegistry.snapshot === 'function'
        ? node.appRegistry.snapshot()
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
        maxStorage,
        // Paid pin-lease marker (incentive/lease). When true, retainUntil is an
        // enforced lease deadline that the custody-expiry sweep acts on and
        // eviction must not shed early. Set by the lease gate on a verified seed.
        leaseManaged: opts.leaseManaged === true
      }, { persist: false })

      try {
        if (typeof node.appRegistry.persistEntry === 'function') {
          await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })
        } else {
          await node.appRegistry.flush({ throwOnError: true })
        }
      } catch (err) {
        if (registrySnapshot && typeof node.appRegistry.restoreSnapshot === 'function') {
          try {
            node.appRegistry.restoreSnapshot(registrySnapshot)
          } catch (rollbackErr) {
            this.emit('registry-rollback-error', {
              appKey: appKeyHex,
              error: (rollbackErr && rollbackErr.message) || String(rollbackErr)
            })
          }
        }
        throw err
      }

      // Signal that we're looking for peers for this drive's cores only
      // after the accepted seed is durably recorded.
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
            // v0.8.28 (#28): pass the LifecycleScope signal through so the
            // inner Promise-shape download path can destroy its blob.core
            // trackers immediately on stop()/self-heal-restart. Without
            // this, raceOr resolves cleanly via AbortError but the inner
            // trackers keep the event loop alive (production-safe but
            // breaks test-runner cleanup; see issue #28).
            await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: 120_000, signal: scope ? scope.signal : null }))
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
  _reconcileSeedOptsOnRepin (appKeyHex, existing, newOpts) {
    const node = this.node
    if (!existing) return

    const newCap = Number.isFinite(newOpts.maxStorage) && newOpts.maxStorage > 0
      ? Math.floor(newOpts.maxStorage)
      : null
    const oldCap = Number.isFinite(existing.maxStorage) && existing.maxStorage > 0
      ? Math.floor(existing.maxStorage)
      : null

    // No cap declared on either side — no change to honor.
    if (newCap === null && oldCap === null) return

    // Cap unchanged — no-op.
    if (newCap === oldCap) return

    // Cap lowered — emit warning, keep the prior (higher) cap. We don't
    // honor shrinking on re-pin because the publisher already accepted
    // the larger commitment; reducing it now would mean unseeding blocks
    // we already replicated. If the publisher really wants to reduce
    // storage, they should unseedApp first, then seed fresh.
    if (newCap !== null && oldCap !== null && newCap < oldCap) {
      this.emit('seed-cap-warning', {
        appKey: appKeyHex,
        reason: 'cap-lowered-on-repin',
        oldCap,
        newCap,
        hint: 'Lowering maxStorage on already-seeded content is not honored on re-pin; relay keeps the higher prior cap. Unseed first if you want to reduce.'
      })
      return
    }

    // Cap raised (or newly declared where it was previously absent).
    //
    // Update entry's stored cap so future re-pin comparisons work, and
    // so the periodic repair monitor / catalog reflect the new value.
    existing.maxStorage = newCap
    if (node.appRegistry && typeof node.appRegistry.update === 'function') {
      try { node.appRegistry.update(appKeyHex, { maxStorage: newCap }) } catch (_) {}
    }

    this.emit('seed-cap-raised', {
      appKey: appKeyHex,
      oldCap,
      newCap,
      anchored: existing.anchored === true,
      hint: oldCap === null
        ? 'Cap declared for previously-uncapped entry; retriggering replication under new cap.'
        : 'Cap raised; retriggering replication to drain blocks the prior cap blocked.'
    })

    // Already replicating from a prior call — let it finish. The entry's
    // maxStorage was updated above, so the periodic repair monitor (which
    // reads entry.maxStorage, not the captured opts) will use the new cap
    // on its next sweep if the in-flight call doesn't suffice.
    if (existing._replicating) return

    // Drive must be open to retrigger. Stale entry (no drive yet, or drive
    // closed) means seeding is happening elsewhere — let that path finish.
    const drive = existing.drive
    if (!drive || drive.closed || drive.closing) return

    existing._replicating = true
    const scope = node && node._scope
    const promise = this._eagerReplicate(appKeyHex, drive, { ...newOpts, maxStorage: newCap }, { source: 'repin-cap-raised' })
      .catch((err) => {
        // Swallow AbortError silently; surface unexpected errors so
        // observers see them (same shape as _trackEagerReplicate).
        if (isAbortError(err)) return
        this.emit('reseed-error', {
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
        // v0.8.28 (#28): same scope-signal threading as _eagerReplicate
        // — destroy inner blob.core trackers on scope abort.
        await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: downloadTimeout, signal: scope ? scope.signal : null }))
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
        this.emit('custody-receipt-error', {
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
        this.emit('custody:share-verify-failed', {
          appKey: appKeyHex,
          intentId: opts.custodyIntentId,
          shareBundleKey: null,
          reason: 'intent-unavailable'
        })
        return null
      }
      const relayPubkey = b4a.toString(node.swarm.keyPair.publicKey, 'hex')
      const bundle = await this._readShareBundle(intent.shareBundleKey)
      const result = verifyShareBundleForRelay(intent, bundle, relayPubkey)
      if (!result.ok) {
        this.emit('custody:share-verify-failed', {
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
      this.emit('custody-receipt', { appKey: appKeyHex, intentId: opts.custodyIntentId, receipt })
      return receipt
    } catch (err) {
      this.emit('custody-receipt-error', {
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
    if (!isValidHexKey(shareBundleKey, 64) || !node.store || !node.swarm) return null
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 30_000
    let core = null
    let joined = false
    try {
      core = node.store.get({ key: b4a.from(shareBundleKey, 'hex') })
      await core.ready()
      // Pull-only join; the swarm 'connection' handler replicates the store.
      const discovery = node.swarm.join(core.discoveryKey, { server: false, client: true })
      joined = true
      if (discovery && typeof discovery.flushed === 'function') {
        await Promise.race([
          discovery.flushed().catch(() => {}),
          new Promise(resolve => setTimeout(resolve, Math.min(timeoutMs, 5_000)))
        ])
      }
      // get() waits for block 0 to replicate from a peer, or rejects on timeout.
      const block = await core.get(0, { timeout: timeoutMs })
      if (!block) return null
      const parsed = JSON.parse(b4a.toString(block))
      return parsed && typeof parsed === 'object' ? parsed : null
    } catch (_) {
      return null
    } finally {
      if (joined && core) {
        try { await node.swarm.leave(core.discoveryKey) } catch (_) {}
      }
      if (core) {
        try { await core.close() } catch (_) {}
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
    const forget = opts.forget !== false
    const node = this.node
    const entry = node.appRegistry.get(appKeyHex)
    if (!entry) return

    if (forget) {
      const registrySnapshot = typeof node.appRegistry.snapshot === 'function'
        ? node.appRegistry.snapshot()
        : null
      node.appRegistry.delete(appKeyHex, { persist: false })
      try {
        if (typeof node.appRegistry.persistDelete === 'function') {
          await node.appRegistry.persistDelete(appKeyHex, { throwOnError: true })
        } else {
          await node.appRegistry.flush({ throwOnError: true })
        }
      } catch (err) {
        if (registrySnapshot && typeof node.appRegistry.restoreSnapshot === 'function') {
          try {
            node.appRegistry.restoreSnapshot(registrySnapshot)
          } catch (rollbackErr) {
            this.emit('registry-rollback-error', {
              appKey: appKeyHex,
              error: (rollbackErr && rollbackErr.message) || String(rollbackErr)
            })
          }
        }
        throw err
      }
    }

    // Destroy persistent download ranges before tearing down the drive
    // so their replicator refs don't leak into the closing core's
    // session pool. Same defensive pattern as _trackEagerReplicate +
    // LifecycleScope from Reliability v2.
    if (Array.isArray(entry.downloadRanges)) {
      for (const dl of entry.downloadRanges) {
        try { if (dl && typeof dl.destroy === 'function') dl.destroy() } catch (_) {}
      }
      entry.downloadRanges = null
    }

    if (node.distributedDriveBridge) {
      node.distributedDriveBridge.unregisterDrive(appKeyHex)
    }

    try { await node.swarm.leave(entry.discoveryKey) } catch (_) {}
    try { await entry.drive.close() } catch (_) {}

    if (!forget) {
      // Keep the persisted entry; just drop the live handles so reseed
      // can rebuild them. reseedFromRegistry overwrites these via
      // _hydrateEntry on the next start(), but null them now so nothing
      // touches the closed drive in the meantime.
      entry.drive = null
      entry.discoveryKey = null
    }

    this.emit('unseeded', { appKey: appKeyHex, forgotten: forget })
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
