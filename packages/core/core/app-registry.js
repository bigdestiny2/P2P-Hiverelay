/**
 * Unified App Registry
 *
 * Single source of truth for all seeded apps. Replaces the scattered
 * seededApps Map, appIndex Map, seeded-apps.json, and app-registry.json
 * with one class that handles:
 *
 *   - In-memory state (apps Map + appId dedup index)
 *   - Disk persistence (auto-saves on every mutation)
 *   - Startup recovery (loads from disk, reseeds drives)
 *   - Catalog generation (for HTTP /catalog.json and P2P broadcast)
 *   - Version deduplication (only keep latest version per appId)
 */

import { readFile, writeFile, rename } from 'fs/promises'
import { join } from 'path'
import { EventEmitter } from 'events'
import {
  compareVersions,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizeStorageClass
} from './constants.js'

const REGISTRY_FILE = 'app-registry.json'

export class AppRegistry extends EventEmitter {
  constructor (storagePath) {
    super()
    this._storagePath = storagePath
    this._filePath = storagePath ? join(storagePath, REGISTRY_FILE) : null

    // Primary state: appKey hex → entry
    this.apps = new Map()

    // Dedup index: appId string → appKey hex (only latest version per appId)
    this.byAppId = new Map()

    this._saving = false
    this._savePending = false
    this._saveDebounceTimer = null
  }

  // ─── Queries ───────────────────────────────────────────────

  get size () { return this.apps.size }

  has (appKey) { return this.apps.has(appKey) }

  get (appKey) { return this.apps.get(appKey) }

  getByAppId (appId) {
    const appKey = this.byAppId.get(appId)
    return appKey ? this.apps.get(appKey) : null
  }

  keys () { return this.apps.keys() }

  values () { return this.apps.values() }

  entries () { return this.apps.entries() }

  [Symbol.iterator] () { return this.apps[Symbol.iterator]() }

  // ─── Mutations ─────────────────────────────────────────────

  _isAppType (entry) {
    return normalizeContentType(entry?.type, 'app') === 'app'
  }

  _isAppIdIndexed (entry) {
    return this._isAppType(entry) && typeof entry?.appId === 'string' && entry.appId.length > 0
  }

  _normalizeEntry (entry = {}) {
    const type = normalizeContentType(entry.type, 'app')
    const blind = entry.blind === true
    const storageClass = normalizeStorageClass(entry.storageClass, blind ? 'temporary' : 'persistent')
    const availabilityClass = normalizeAvailabilityClass(entry.availabilityClass, blind ? 'atomic-handoff' : 'always-on')
    const parentKey = typeof entry.parentKey === 'string' && entry.parentKey.length > 0
      ? entry.parentKey
      : null
    const mountPath = typeof entry.mountPath === 'string' && entry.mountPath.trim().length > 0
      ? entry.mountPath.trim()
      : null
    const categories = Array.isArray(entry.categories)
      ? [...new Set(entry.categories.map(c => String(c).trim()).filter(Boolean))]
      : null

    // Anchor fields — distinguishes "we accepted to seed" from "we actually
    // have replicated blocks." A drive can be in the registry without being
    // anchored (publisher went offline before we pulled), and we want
    // visibility on that.
    const anchored = entry.anchored === true
    const anchoredAt = anchored && typeof entry.anchoredAt === 'number' ? entry.anchoredAt : null
    const anchoredLength = typeof entry.anchoredLength === 'number' ? entry.anchoredLength : 0
    const lastAnchorCheck = typeof entry.lastAnchorCheck === 'number' ? entry.lastAnchorCheck : null

    // v0.8.12: per-app maxStorage from the seed request. Persisted so we
    // can compare on re-pin (cap-up vs cap-down vs unchanged) instead of
    // forgetting it between restarts. See AppLifecycle._reconcileSeedOptsOnRepin.
    const maxStorage = Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
      ? Math.floor(entry.maxStorage)
      : null

    return {
      ...entry,
      type,
      blind,
      storageClass,
      availabilityClass,
      parentKey,
      mountPath,
      categories,
      anchored,
      anchoredAt,
      anchoredLength,
      lastAnchorCheck,
      maxStorage
    }
  }

  /**
   * Register a seeded app. Automatically persists and emits change event.
   */
  set (appKey, entry) {
    const normalized = this._normalizeEntry(entry)
    this.apps.set(appKey, normalized)

    // Update dedup index if entry has an appId
    if (this._isAppIdIndexed(normalized)) {
      this.byAppId.set(normalized.appId, appKey)
    }

    this._scheduleSave()
    this.emit('change', { type: 'set', appKey, entry: normalized })
  }

  /**
   * Update metadata on an existing entry without replacing it.
   */
  update (appKey, updates) {
    const entry = this.apps.get(appKey)
    if (!entry) return false

    const hadIndexedAppId = this._isAppIdIndexed(entry)
    const previousAppId = entry.appId
    Object.assign(entry, this._normalizeEntry({ ...entry, ...updates }))

    // Update dedup index when app identity changed
    if (hadIndexedAppId && previousAppId && this.byAppId.get(previousAppId) === appKey) {
      this.byAppId.delete(previousAppId)
    }
    if (this._isAppIdIndexed(entry)) {
      this.byAppId.set(entry.appId, appKey)
    }

    this._scheduleSave()
    this.emit('change', { type: 'update', appKey, entry })
    return true
  }

  /**
   * Remove a seeded app. Automatically persists and emits change event.
   */
  delete (appKey) {
    const entry = this.apps.get(appKey)
    if (!entry) return false

    // Clean dedup index
    if (this._isAppIdIndexed(entry) && this.byAppId.get(entry.appId) === appKey) {
      this.byAppId.delete(entry.appId)
    }

    this.apps.delete(appKey)
    this._scheduleSave()
    this.emit('change', { type: 'delete', appKey })
    return true
  }

  // ─── Anchor management ────────────────────────────────────────
  //
  // An "anchored" entry is one where the relay has actually replicated
  // blocks (length > 0), as opposed to merely registered as accepted.
  // Distinguishing the two prevents the relay from claiming to serve
  // content it has no copy of — which is what created the "drive
  // disappeared" failure mode users hit. Catalog/capability-doc consumers
  // can check `anchored: true` to know they're talking to a relay that
  // can actually serve the content, not just one that remembers the key.

  /**
   * Mark an app as anchored (we have replicated blocks). Idempotent —
   * subsequent calls only update `anchoredLength` and `lastAnchorCheck`.
   * @param {string} appKey
   * @param {number} length - latest hypercore length we observed
   */
  setAnchored (appKey, length = 0) {
    const entry = this.apps.get(appKey)
    if (!entry) return false

    const wasAnchored = entry.anchored === true
    const now = Date.now()
    entry.anchored = true
    entry.anchoredLength = Math.max(entry.anchoredLength || 0, length || 0)
    entry.lastAnchorCheck = now
    if (!wasAnchored) entry.anchoredAt = now

    this._scheduleSave()
    if (!wasAnchored) {
      this.emit('change', { type: 'anchored', appKey, entry })
    } else {
      this.emit('change', { type: 'anchor-update', appKey, entry })
    }
    return true
  }

  /**
   * Mark an entry as no longer anchored (drive lost, content gone).
   * Used when on-startup verification finds a registry entry whose
   * underlying hypercore has length 0.
   * @param {string} appKey
   * @param {string} reason - human-readable reason for observability
   */
  clearAnchored (appKey, reason = null) {
    const entry = this.apps.get(appKey)
    if (!entry) return false
    if (entry.anchored !== true) return false
    entry.anchored = false
    entry.anchoredLength = 0
    entry.lastAnchorCheck = Date.now()
    this._scheduleSave()
    this.emit('change', { type: 'unanchored', appKey, entry, reason })
    return true
  }

  /**
   * Update lastAnchorCheck without changing anchored state — useful when
   * we did a check, found no blocks, and want to record that we tried.
   */
  recordAnchorCheck (appKey) {
    const entry = this.apps.get(appKey)
    if (!entry) return false
    entry.lastAnchorCheck = Date.now()
    this._scheduleSave()
    return true
  }

  /**
   * Aggregate anchor stats across the registry. Useful for capability
   * docs, dashboards, and operator visibility into the gap between
   * "accepted" and "actually serving."
   */
  anchorStats () {
    let total = 0
    let anchored = 0
    let unanchored = 0
    let neverChecked = 0
    for (const entry of this.apps.values()) {
      total++
      if (entry.anchored === true) anchored++
      else unanchored++
      if (!entry.lastAnchorCheck) neverChecked++
    }
    return { total, anchored, unanchored, neverChecked }
  }

  // ─── Catalog Output ────────────────────────────────────────

  _shouldRedactEntry (entry, opts = {}) {
    // The blind flag is the publisher's privacy commitment — the relay
    // honors it unconditionally, regardless of caller opts or operator
    // config. opts.redactPrivate only controls whether non-blind
    // privacy-tier entries also get redacted.
    //
    // Without this unconditional check, a custody.redactedCatalog:false
    // operator config OR a catalog() call site that forgets to pass
    // redactPrivate would expose blind entries' full metadata.
    //
    // See docs/audit/2026-05-19-blind-path-audit.md (Path 3).
    if (entry.blind === true) return true
    if (opts.redactPrivate !== true) return false
    const privacyTier = String(entry.privacyTier || 'public').toLowerCase()
    return privacyTier !== 'public' || entry.metadataVisibility === 'redacted'
  }

  _redactCatalogEntry (catalogEntry, entry, opts = {}) {
    if (!this._shouldRedactEntry(entry, opts)) return catalogEntry

    return {
      ...catalogEntry,
      appKey: entry.blindContentId || null,
      parentKey: null,
      mountPath: null,
      id: entry.blindContentId || 'private-content',
      name: 'Private Content',
      description: '',
      author: 'redacted',
      version: null,
      driveKey: null,
      discoveryKey: null,
      categories: ['private'],
      redacted: true,
      addressKeyRedacted: true,
      metadataVisibility: 'redacted',
      blindContentId: entry.blindContentId || null,
      // v0.8.18 Phase A: provenance fields MUST be stripped for blind/
      // redacted entries — leaking publisherPubkey would link the
      // publisher to the blind drive; leaking durability/retainUntil
      // would reveal commitment signals about "interesting" content.
      // Cascades with the new provenance fields added to catalog()
      // and catalogForBroadcast().
      publisherPubkey: null,
      durability: 0,
      revocable: true,
      retainUntil: null
    }
  }

  /**
   * Generate the app catalog for HTTP /catalog.json and P2P broadcast.
   * Returns array of { appKey, appId, version, discoveryKey, blind, seededAt, name, description }
   * No drive reads needed — all metadata comes from the registry.
   */
  catalog (opts = {}) {
    const items = []
    const seen = new Map() // appId → index in items array (dedup for app type)
    const now = Date.now()

    for (const [appKey, entry] of this.apps) {
      const type = normalizeContentType(entry.type, 'app')
      const appId = entry.appId || appKey.slice(0, 12)
      const catalogEntry = this._redactCatalogEntry({
        appKey,
        type,
        parentKey: entry.parentKey || null,
        mountPath: entry.mountPath || null,
        id: appId,
        name: entry.name || entry.appId || 'Unknown App',
        description: entry.description || '',
        author: entry.author || 'anonymous',
        version: entry.version || '1.0.0',
        driveKey: appKey,
        discoveryKey: entry.discoveryKey
          ? (typeof entry.discoveryKey === 'string' ? entry.discoveryKey : entry.discoveryKey.toString('hex'))
          : null,
        blind: entry.blind || false,
        storageClass: normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent'),
        availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on'),
        categories: entry.categories || ['uncategorized'],
        privacyTier: entry.privacyTier || 'public',
        seededAt: entry.startedAt || entry.seededAt || now,
        // Anchor signal — clients can prefer relays whose entries are
        // anchored=true (they actually have blocks) over ones that
        // merely remember accepting the seed.
        anchored: entry.anchored === true,
        anchoredAt: entry.anchoredAt || null,
        anchoredLength: entry.anchoredLength || 0,
        // Durability tier — surfaced so peer relays' AutoHeal scheduler
        // can identify which drives need active replication maintenance.
        // Defaults to 0 (standard) if absent from older entries.
        durability: entry.durability || 0,
        // Revocability — surfaced so quorum clients and ForkDetector can
        // distinguish "publisher can pull this back" from "permanent
        // commitment" content.
        revocable: entry.revocable !== false,
        // v0.8.18 Phase A: surface publisher provenance so downstream
        // relays receiving this catalog (via federation HTTP or P2P
        // broadcast) can distinguish "published-with-commitment" from
        // "pure-anonymous-mirror." Redacted entries strip these in
        // _redactCatalogEntry — never leaked for blind drives.
        publisherPubkey: entry.publisherPubkey || null,
        retainUntil: entry.retainUntil || null
      }, entry, opts)

      // Dedup app entries by appId — keep latest version
      if (type === 'app') {
        const existingIdx = seen.get(appId)
        if (existingIdx !== undefined) {
          const existing = items[existingIdx]
          if (compareVersions(catalogEntry.version, existing.version) > 0) {
            items[existingIdx] = catalogEntry
          }
        } else {
          seen.set(appId, items.length)
          items.push(catalogEntry)
        }
      } else {
        items.push(catalogEntry)
      }
    }

    return items
  }

  catalogByType (type) {
    const normalizedType = normalizeContentType(type, null)
    if (!normalizedType) return []
    return this.catalog().filter(entry => entry.type === normalizedType)
  }

  catalogByParent (parentKey) {
    if (!parentKey) return []
    return this.catalog().filter(entry => entry.parentKey === parentKey)
  }

  /**
   * Lightweight version for P2P MSG_APP_CATALOG broadcast.
   */
  catalogForBroadcast () {
    const apps = []
    const now = Date.now()
    for (const [appKey, entry] of this.apps) {
      const redacted = this._shouldRedactEntry(entry, { redactPrivate: true })
      apps.push({
        appKey: redacted ? null : appKey,
        appId: redacted ? null : (entry.appId || null),
        type: normalizeContentType(entry.type, 'app'),
        parentKey: redacted ? null : (entry.parentKey || null),
        mountPath: redacted ? null : (entry.mountPath || null),
        version: redacted ? null : (entry.version || null),
        discoveryKey: entry.discoveryKey
          ? (redacted ? null : (typeof entry.discoveryKey === 'string' ? entry.discoveryKey : entry.discoveryKey.toString('hex')))
          : null,
        blind: entry.blind || false,
        storageClass: normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent'),
        availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on'),
        privacyTier: entry.privacyTier || 'public',
        seededAt: entry.startedAt || entry.seededAt || now,
        redacted,
        metadataVisibility: redacted ? 'redacted' : 'public',
        blindContentId: redacted ? (entry.blindContentId || null) : null,
        // Anchor signal — tells peer relays whether we actually have
        // blocks. Receiving relay uses this to trigger targeted repair
        // when they have the drive unanchored and we have it anchored.
        anchored: entry.anchored === true,
        // v0.8.18 Phase A: provenance fields. For non-redacted entries,
        // carry publisher commitments downstream so federation accept
        // logic (and the future durability-floor policy) can distinguish
        // published-with-commitment from pure-anonymous-gossip. Redacted
        // entries (blind drives) MUST not surface these — would leak
        // publisher identity + commitment signals about the blind drive.
        publisherPubkey: redacted ? null : (entry.publisherPubkey || null),
        durability: redacted ? 0 : (entry.durability || 0),
        revocable: redacted ? true : (entry.revocable !== false),
        retainUntil: redacted ? null : (entry.retainUntil || null)
      })
    }
    return apps
  }

  // ─── Deduplication ─────────────────────────────────────────

  /**
   * Check if adding an app with this appId would conflict with an existing one.
   * Returns { conflict: false } or { conflict: true, existingKey, existingVersion, shouldReplace }
   */
  checkConflict (appId, appKey, version) {
    const existingKey = this.byAppId.get(appId)
    if (!existingKey || existingKey === appKey) return { conflict: false }

    const existing = this.apps.get(existingKey)
    if (!existing) return { conflict: false }

    return {
      conflict: true,
      existingKey,
      existingVersion: existing.version || '0.0.0',
      shouldReplace: compareVersions(version, existing.version || '0.0.0') >= 0
    }
  }

  // ─── Persistence ───────────────────────────────────────────

  /**
   * Load registry from disk. Returns entries array for reseeding.
   */
  async load () {
    if (!this._filePath) return []

    try {
      const data = JSON.parse(await readFile(this._filePath, 'utf8'))

      // Support both array format (old seeded-apps.json) and object format
      const entries = Array.isArray(data) ? data : Object.values(data)

      // Populate in-memory state from disk
      for (const entry of entries) {
        const appKey = entry.appKey || entry.driveKey
        if (!appKey) continue

        this.apps.set(appKey, {
          startedAt: entry.startedAt || entry.seededAt || Date.now(),
          appId: entry.appId || entry.name || null,
          type: normalizeContentType(entry.type, 'app'),
          parentKey: entry.parentKey || null,
          mountPath: entry.mountPath || null,
          version: entry.version || null,
          name: entry.name || entry.appId || null,
          description: entry.description || '',
          author: entry.author || null,
          blind: entry.blind || false,
          storageClass: normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent'),
          availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on'),
          custodyIntentId: entry.custodyIntentId || null,
          blindContentId: entry.blindContentId || null,
          ciphertextRoot: entry.ciphertextRoot || null,
          contentVersion: Number.isFinite(entry.contentVersion) ? entry.contentVersion : null,
          retainUntil: entry.retainUntil || null,
          shardIds: Array.isArray(entry.shardIds) ? entry.shardIds : null,
          privacyTier: entry.privacyTier || 'public',
          // v0.8.18 Phase A: restore provenance from disk so catalog and
          // catalogForBroadcast surface the publisher's commitments after
          // restart. Older registry files won't have these — null/0/true
          // defaults mean "no provenance recorded" (matches pre-v0.8.18).
          publisherPubkey: entry.publisherPubkey || null,
          durability: Number.isFinite(entry.durability) ? entry.durability : 0,
          revocable: entry.revocable !== false,
          categories: entry.categories || null,
          bytesServed: 0,
          // Anchor state restored from disk so we don't forget what we
          // know between restarts. The periodic anchor check will refresh
          // these soon after startup.
          anchored: entry.anchored === true,
          anchoredAt: entry.anchoredAt || null,
          anchoredLength: typeof entry.anchoredLength === 'number' ? entry.anchoredLength : 0,
          lastAnchorCheck: entry.lastAnchorCheck || null,
          // v0.8.12: per-app maxStorage cap, used by re-pin reconciliation
          // to detect cap-up vs cap-down without losing the prior value
          // across restarts. Older registry files won't have this — null
          // means "no cap declared at seed time."
          maxStorage: Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
            ? Math.floor(entry.maxStorage)
            : null,
          // drive and discoveryKey are set during reseeding
          drive: null,
          discoveryKey: null
        })

        if (entry.appId && normalizeContentType(entry.type, 'app') === 'app') {
          this.byAppId.set(entry.appId, appKey)
        }
      }

      return entries.map(e => ({
        appKey: e.appKey || e.driveKey,
        appId: e.appId || e.name || null,
        type: normalizeContentType(e.type, 'app'),
        parentKey: e.parentKey || null,
        mountPath: e.mountPath || null,
        version: e.version || null,
        privacyTier: e.privacyTier || 'public',
        blind: e.blind || false,
        storageClass: normalizeStorageClass(e.storageClass, e.blind ? 'temporary' : 'persistent'),
        availabilityClass: normalizeAvailabilityClass(e.availabilityClass, e.blind ? 'atomic-handoff' : 'always-on'),
        custodyIntentId: e.custodyIntentId || null,
        blindContentId: e.blindContentId || null,
        ciphertextRoot: e.ciphertextRoot || null,
        contentVersion: Number.isFinite(e.contentVersion) ? e.contentVersion : null,
        retainUntil: e.retainUntil || null,
        shardIds: Array.isArray(e.shardIds) ? e.shardIds : null,
        // v0.8.18 Phase A: forward provenance to the reseed call so it
        // makes it back into the freshly-initialized in-memory entry
        // post-restart. Without this, even though save() now persists
        // these, _seedAppInner wouldn't see them on reseed and the
        // entry would re-set publisherPubkey: opts.publisherPubkey (which
        // would be undefined), clobbering what we just loaded.
        publisherPubkey: e.publisherPubkey || null,
        durability: Number.isFinite(e.durability) ? e.durability : 0,
        revocable: e.revocable !== false,
        // v0.8.12: surface persisted maxStorage so reseedFromRegistry
        // can pass it back through seedApp and the size-check fires
        // on startup too (not just on fresh publisher seed requests).
        maxStorage: Number.isFinite(e.maxStorage) && e.maxStorage > 0
          ? Math.floor(e.maxStorage)
          : null
      })).filter(e => e.appKey)
    } catch (_) {
      return []
    }
  }

  /**
   * Save registry to disk. Uses atomic write (write temp, rename).
   * Coalesces rapid writes — only one save happens at a time.
   */
  async save () {
    if (!this._filePath) return

    if (this._saving) {
      this._savePending = true
      return
    }

    this._saving = true
    try {
      const entries = []
      for (const [appKey, entry] of this.apps) {
        entries.push({
          appKey,
          appId: entry.appId || null,
          type: normalizeContentType(entry.type, 'app'),
          parentKey: entry.parentKey || null,
          mountPath: entry.mountPath || null,
          version: entry.version || null,
          name: entry.name || entry.appId || null,
          description: entry.description || '',
          author: entry.author || null,
          blind: entry.blind || false,
          storageClass: normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent'),
          availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on'),
          custodyIntentId: entry.custodyIntentId || null,
          blindContentId: entry.blindContentId || null,
          ciphertextRoot: entry.ciphertextRoot || null,
          contentVersion: Number.isFinite(entry.contentVersion) ? entry.contentVersion : null,
          retainUntil: entry.retainUntil || null,
          shardIds: Array.isArray(entry.shardIds) ? entry.shardIds : null,
          privacyTier: entry.privacyTier || 'public',
          // v0.8.18 Phase A: persist provenance so it survives restart.
          // Without this, federation broadcasts would lose publisher
          // attribution on every service bounce — the in-memory entry
          // sets these via _seedAppInner but they were vanishing on disk.
          publisherPubkey: entry.publisherPubkey || null,
          durability: Number.isFinite(entry.durability) ? entry.durability : 0,
          revocable: entry.revocable !== false,
          categories: entry.categories || null,
          startedAt: entry.startedAt || Date.now(),
          discoveryKey: entry.discoveryKey
            ? (typeof entry.discoveryKey === 'string' ? entry.discoveryKey : entry.discoveryKey.toString('hex'))
            : null,
          // Anchor state — persisted so we don't lose the "we have blocks"
          // signal across restarts. Fresh check still runs on startup, but
          // until it does, the registry remembers the last known state.
          anchored: entry.anchored === true,
          anchoredAt: entry.anchoredAt || null,
          anchoredLength: entry.anchoredLength || 0,
          lastAnchorCheck: entry.lastAnchorCheck || null,
          // v0.8.12: per-app maxStorage cap, persisted so re-pin
          // reconciliation can compare across restarts and the size-check
          // fires on reseed too. Null for entries that predate this field.
          maxStorage: Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
            ? Math.floor(entry.maxStorage)
            : null
        })
      }

      const tmpPath = this._filePath + '.tmp'
      await writeFile(tmpPath, JSON.stringify(entries, null, 2))
      await rename(tmpPath, this._filePath)
    } catch (err) {
      this.emit('error', { context: 'save', error: err })
    } finally {
      this._saving = false
      if (this._savePending) {
        this._savePending = false
        this.save().catch(() => {})
      }
    }
  }

  _scheduleSave () {
    if (this._saveDebounceTimer) clearTimeout(this._saveDebounceTimer)
    this._saveDebounceTimer = setTimeout(() => {
      this._saveDebounceTimer = null
      this.save().catch(() => {})
    }, 5000)
  }

  /**
   * Force an immediate save, bypassing the debounce timer.
   * Call during shutdown to ensure state is persisted.
   */
  async flush () {
    if (this._saveDebounceTimer) {
      clearTimeout(this._saveDebounceTimer)
      this._saveDebounceTimer = null
    }
    await this.save()
  }
}
