import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { updateWithTimeout, downloadWithTimeout, getDriveSize } from './cancellable-drive-update.js'
import { isAbortError } from './lifecycle-scope.js'
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

  async reseedFromRegistry () {
    const node = this.node
    const entries = await node.appRegistry.load()
    if (!entries.length) {
      await this.migrateOldSeededApps()
      return
    }

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
            : undefined
        })
        this.emit('reseeded', { appKey: entry.appKey })
      } catch (err) {
        this.emit('reseed-error', { appKey: entry.appKey, error: err })
      }
    }
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
        this._reconcileSeedOptsOnRepin(appKeyHex, existing, opts)
        return { discoveryKey: dkHex, alreadySeeded: true }
      }
      // else: placeholder entry from load() — fall through.
    }

    // Evict oldest app if storage capacity would be exceeded
    if (node.config.enableEviction !== false && node.seeder.totalBytesStored >= node.config.maxStorageBytes && this.seededApps.size > 0) {
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
    const drive = new Hyperdrive(node.store, appKey)

    try {
      await drive.ready()

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
          try {
            await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: 120_000 }))
          } catch (err) {
            if (isAbortError(err)) return
            // partial download is fine; version is what matters — keep going
          }

          if (aborted() || drive.closed || drive.closing) return

          // After content is downloaded, read manifest and deduplicate.
          // Idempotent — safe to call on retrigger.
          await this._indexAppManifest(appKeyHex, drive)

          // Mark anchored — we have actual replicated blocks. This is the
          // signal that distinguishes "we accepted the seed" from "we
          // can actually serve the content." Catalog/capability docs
          // surface this so clients can prefer relays that have the data.
          if (node.appRegistry && typeof node.appRegistry.setAnchored === 'function') {
            node.appRegistry.setAnchored(appKeyHex, drive.version)
            await this._recordCustodyReceipt(appKeyHex, opts, drive.version)
            this.emit('anchored', { appKey: appKeyHex, version: drive.version, source })
          }

          this.emit('reseeded', { appKey: appKeyHex, version: drive.version, source })
          return
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

    // We have metadata; pull blob content (cancellable on timeout)
    try {
      try {
        await raceOr(downloadWithTimeout(drive, '/', { timeoutMs: downloadTimeout }))
      } catch (err) {
        if (isAbortError(err)) return false
        // partial download still counts — version is what matters
      }

      if ((scope && scope.aborted) || drive.closed || drive.closing) return false

      if (drive.version > 0) {
        node.appRegistry.setAnchored(appKeyHex, drive.version)
        await this._recordCustodyReceipt(appKeyHex, entry, drive.version)
        this.emit('anchored', { appKey: appKeyHex, version: drive.version, source: 'repair' })
        return true
      }
    } catch (err) {
      if (isAbortError(err)) return false
      this.emit('repair-download-failed', { appKey: appKeyHex, error: err.message })
    }
    return false
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

  async _recordCustodyReceipt (appKeyHex, opts = {}, contentVersion = 0) {
    const node = this.node
    if (!opts.blind || !opts.custodyIntentId || !node.seedingRegistry || !node.swarm?.keyPair) return null
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
        retainUntil: opts.retainUntil || (Date.now() + 30 * 24 * 60 * 60 * 1000)
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

  async unseedApp (appKeyHex) {
    const node = this.node
    const entry = node.appRegistry.get(appKeyHex)
    if (!entry) return

    if (node.distributedDriveBridge) {
      node.distributedDriveBridge.unregisterDrive(appKeyHex)
    }

    try { await node.swarm.leave(entry.discoveryKey) } catch (_) {}
    try { await entry.drive.close() } catch (_) {}
    node.appRegistry.delete(appKeyHex) // auto-cleans dedup index + persists

    this.emit('unseeded', { appKey: appKeyHex })
  }

  /**
   * Authenticated unseed: verify the publisher signature before unseeding.
   * The publisher must sign (appKey + 'unseed' + timestamp) with the key
   * that originally published the app (stored in appRegistry.publisherPubkey).
   */
  verifyUnseedRequest (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    const node = this.node
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
