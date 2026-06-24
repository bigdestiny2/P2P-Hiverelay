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

import { readFile, writeFile, rename, unlink } from 'fs/promises'
import { join } from 'path'
import { EventEmitter } from 'events'
import Hyperbee from 'hyperbee'
import {
  compareVersions,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizeStorageClass
} from './constants.js'

const REGISTRY_FILE = 'app-registry.json'
const BEE_CORE_NAME = 'app-registry-v1'
const EVICTED_FILE = 'evicted.json'
const MAX_TOMBSTONES = 5000

/**
 * Collapse already-built catalog rows: for `app`-type rows sharing an appId,
 * keep only the highest version. The same latest-version-wins rule catalog()
 * applies inline (see ~`if (type === 'app')` below); factored here so the P2P
 * broadcast can't drift from the HTTP view. Rows that are non-`app` or carry a
 * null id (redacted/blind) are never collapsed — they pass through untouched.
 */
function dedupLatestByAppId (rows, idField = 'appId') {
  const out = []
  const seen = new Map() // id -> index in out
  for (const r of rows) {
    const id = r[idField]
    if (r.type !== 'app' || id == null) { out.push(r); continue }
    const idx = seen.get(id)
    if (idx === undefined) {
      seen.set(id, out.length)
      out.push(r)
    } else if (compareVersions(r.version || '0.0.0', out[idx].version || '0.0.0') > 0) {
      out[idx] = r
    }
  }
  return out
}

export class AppRegistry extends EventEmitter {
  /**
   * @param {string|null} storagePath - directory containing app-registry.json
   * @param {object} [opts]
   * @param {Corestore} [opts.store] - if provided, persistence uses a Hyperbee
   *   on this corestore. JSON file is still read once for migration on first
   *   load, then renamed to .bak. Without a store, falls back to legacy
   *   JSON-blob persistence (pre-v0.8.25 behavior).
   */
  constructor (storagePath, opts = {}) {
    super()
    this._storagePath = storagePath
    this._filePath = storagePath ? join(storagePath, REGISTRY_FILE) : null

    // v0.8.25 — Hyperbee persistence on the relay's Corestore. Set lazily
    // via setStore() if the corestore isn't ready at construction time
    // (RelayNode creates the store before the registry but doesn't pass
    // it through the constructor today).
    this._store = opts.store || null
    this._bee = null
    this._beeReady = false
    // Track in-flight bee writes so flush() can await them. Each
    // _persistEntryToBee / _deleteEntryFromBee adds its promise; on
    // settle (success OR error) it's removed.
    this._pendingBeeOps = new Set()
    // Serialize bee writes. Concurrent bee.put()/del() calls are a
    // read-modify-write race that silently drops entries (seeding two
    // apps in quick succession could lose one). Chain every write onto
    // this tail so they apply strictly in order.
    this._beeWriteTail = Promise.resolve()

    // Primary state: appKey hex → entry
    this.apps = new Map()

    // Dedup index: appId string → appKey hex (only latest version per appId)
    this.byAppId = new Map()

    // Legacy JSON debouncer state — used only when no store is configured.
    this._saving = false
    this._savePending = false
    this._saveIdleWaiters = []
    this._saveDebounceTimer = null

    // Eviction tombstones (Phase A, 2026-06-11): appKey hex -> evictedAt.
    // Lives in a JSON sidecar (atomic tmp+rename), deliberately OUTSIDE
    // the bee — the bee's rows hydrate as apps on load, and a tombstone
    // must do the opposite: prevent boot-replay and replication-repair
    // from resurrecting an entry this relay deliberately shed, unless the
    // network later falls under the replica floor (the repair gate calls
    // clearEvicted then).
    this.evicted = new Map()
    this._evictedPath = storagePath ? join(storagePath, EVICTED_FILE) : null
    this._evictedPersistTail = Promise.resolve()
  }

  // ─── Eviction tombstones ──────────────────────────────────────────

  markEvicted (appKeyHex, at = Date.now()) {
    this.evicted.set(appKeyHex, at)
    // Bound the set: oldest tombstones fall off — by then the entry is
    // either long gone network-wide or legitimately re-adoptable.
    if (this.evicted.size > MAX_TOMBSTONES) {
      const oldest = [...this.evicted.entries()].sort((a, b) => a[1] - b[1])
      for (let i = 0; i < oldest.length - MAX_TOMBSTONES; i++) this.evicted.delete(oldest[i][0])
    }
    this._persistEvicted()
  }

  isEvicted (appKeyHex) {
    return this.evicted.has(appKeyHex)
  }

  clearEvicted (appKeyHex) {
    if (!this.evicted.delete(appKeyHex)) return
    this._persistEvicted()
  }

  _persistEvicted () {
    if (!this._evictedPath) return
    this._evictedPersistTail = this._evictedPersistTail
      .then(() => this._writeEvicted())
      .catch(() => {})
    return this._evictedPersistTail
  }

  async _writeEvicted () {
    const tmp = this._evictedPath + '.tmp'
    try {
      await writeFile(tmp, JSON.stringify(Object.fromEntries(this.evicted)))
      await rename(tmp, this._evictedPath)
    } catch (err) {
      try { await unlink(tmp) } catch {}
      this.emit('error', { context: 'persist-evicted', error: err })
    }
  }

  async _loadEvicted () {
    if (!this._evictedPath) return
    try {
      const data = JSON.parse(await readFile(this._evictedPath, 'utf8'))
      for (const [k, v] of Object.entries(data)) {
        if (typeof v === 'number') this.evicted.set(k, v)
      }
    } catch {
      // Missing/corrupt sidecar -> no tombstones. Worst case the relay
      // re-adopts and a later sweep re-evicts.
    }
  }

  /**
   * v0.8.25 — attach a Corestore so persistence uses a Hyperbee instead of
   * the JSON-blob file. Must be called BEFORE load(). After this, every
   * mutation writes one block to the bee instead of rewriting the whole
   * registry file.
   *
   * The bee lives on a namespace of the supplied store, so it doesn't
   * collide with any other Hypercore the corestore manages.
   *
   * @param {Corestore} store
   */
  setStore (store) {
    if (!store) return
    if (this._bee || this._beeReady) {
      throw new Error('setStore must be called before load()')
    }
    this._store = store
  }

  /**
   * Drop the current Hyperbee handle so a later setStore()/load() can
   * reopen against a fresh Corestore. Used on self-heal restart, where
   * stop() closes the corestore and start() recreates it: the old `_bee`
   * is backed by the now-closed core, so reads (reseedFromRegistry) would
   * fail with SESSION_CLOSED and silently reseed nothing. We do NOT close
   * the bee here — its underlying core is already closed with the store.
   * The in-memory `apps`/`byAppId` maps are left intact; load() re-hydrates
   * them from the reopened bee.
   */
  detachStore () {
    this._bee = null
    this._beeReady = false
    this._store = null
    this._pendingBeeOps.clear()
    this._beeWriteTail = Promise.resolve()
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

  snapshot () {
    return {
      apps: new Map(this.apps),
      byAppId: new Map(this.byAppId),
      evicted: new Map(this.evicted)
    }
  }

  restoreSnapshot (snapshot = {}) {
    this.apps.clear()
    this.byAppId.clear()
    this.evicted.clear()
    for (const [key, value] of snapshot.apps || []) this.apps.set(key, value)
    for (const [key, value] of snapshot.byAppId || []) this.byAppId.set(key, value)
    for (const [key, value] of snapshot.evicted || []) this.evicted.set(key, value)
  }

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

    // v0.17.0: optional display icon for catalog/PearBrowser rendering.
    // A string the client resolves — a drive-relative path ('/icon.png'),
    // an https URL, or a small data: URI. Capped to keep catalog rows
    // bounded; blind drives strip it in _redactCatalogEntry.
    const icon = typeof entry.icon === 'string' && entry.icon.trim()
      ? entry.icon.trim().slice(0, 512)
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
      icon,
      anchored,
      anchoredAt,
      anchoredLength,
      lastAnchorCheck,
      maxStorage,
      // Paid pin-lease marker. When true, retainUntil is an enforced lease
      // deadline (the custody-expiry sweep unseeds past it). See incentive/lease.
      leaseManaged: entry.leaseManaged === true
    }
  }

  /**
   * Register a seeded app. Automatically persists and emits change event.
   */
  set (appKey, entry, opts = {}) {
    const normalized = this._normalizeEntry(entry)
    this.apps.set(appKey, normalized)

    // Update dedup index if entry has an appId
    if (this._isAppIdIndexed(normalized)) {
      this.byAppId.set(normalized.appId, appKey)
    }

    if (opts.persist !== false) this._scheduleSave(appKey)
    this.emit('change', { type: 'set', appKey, entry: normalized })
  }

  /**
   * Update metadata on an existing entry without replacing it.
   */
  update (appKey, updates, opts = {}) {
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

    if (opts.persist !== false) this._scheduleSave(appKey)
    this.emit('change', { type: 'update', appKey, entry })
    return true
  }

  /**
   * Remove a seeded app. Automatically persists and emits change event.
   */
  delete (appKey, opts = {}) {
    const entry = this.apps.get(appKey)
    if (!entry) return false

    // Clean dedup index
    if (this._isAppIdIndexed(entry) && this.byAppId.get(entry.appId) === appKey) {
      this.byAppId.delete(entry.appId)
    }

    this.apps.delete(appKey)
    if (opts.persist !== false) this._scheduleSave(appKey, { deleted: true })
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

    this._scheduleSave(appKey)
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
    this._scheduleSave(appKey)
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
    this._scheduleSave(appKey)
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
      // v0.17.0: strip the display icon for blind/redacted drives — a
      // drive-relative icon path would leak the addressKey, an external
      // URL could beacon, and either reveals "this blind drive looks
      // like app X." Cascades with the name/description redaction above.
      icon: null,
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
      retainUntil: null,
      // custodyIntentId is NOT redacted: it is already a public identifier
      // exposed by GET /api/custody/{intentId}/status. Surfacing it on
      // the catalog entry only reveals the linkage (intent ↔ appRegistry
      // entry), which is the load-bearing diagnostic for the claim-path
      // expiry sweep (_runCustodyExpiryPass in relay-node/index.js) —
      // operators need to verify the entry carries the binding the sweep
      // gates on (`if (custodyIntentId && this.seedingRegistry) ...`).
      custodyIntentId: entry.custodyIntentId || null
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
        // v0.17.0: display icon for catalog/PearBrowser app tiles (null if
        // unset). Redacted for blind drives in _redactCatalogEntry.
        icon: entry.icon || null,
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
        retainUntil: entry.retainUntil || null,
        // custodyIntentId — atomic-custody binding from seed opts. Surfaced
        // here so the claim-path expiry sweep diagnostic can verify the
        // entry is linked to its custody intent. Preserved through
        // _redactCatalogEntry because the identifier itself is already
        // public (GET /api/custody/{intentId}/status) — only the linkage
        // is new info, and the linkage is exactly what the sweep gates on.
        custodyIntentId: entry.custodyIntentId || null
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
    // Dedup app-type rows by appId (keep highest version) — catalog() already
    // does this for the HTTP view, but the P2P broadcast previously emitted one
    // row per registry entry, leaking superseded versions to peers. Redacted
    // rows (appId null) + non-'app' types pass through untouched.
    return dedupLatestByAppId(apps)
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
   * v0.8.25 — open the Hyperbee on the configured Corestore. Idempotent.
   * Returns the bee handle. Stub-friendly: if `_store` looks like a Corestore
   * but bee construction fails (test-stub case), returns null and the
   * caller falls back to legacy JSON behavior.
   */
  async _openBee () {
    if (this._bee) return this._bee
    if (!this._store) return null
    try {
      const core = this._store.get({ name: BEE_CORE_NAME })
      if (core && typeof core.ready === 'function') {
        await core.ready()
      }
      this._bee = new Hyperbee(core, {
        keyEncoding: 'utf-8',
        valueEncoding: 'json'
      })
      if (typeof this._bee.ready === 'function') {
        await this._bee.ready()
      }
      this._beeReady = true
      return this._bee
    } catch (err) {
      // Defensive: in unit tests with non-Corestore stubs, fall back to
      // the JSON path silently. Production Corestores never reach this.
      this._bee = null
      this._beeReady = false
      this._store = null
      return null
    }
  }

  /**
   * v0.8.25 — one-time migration from JSON to bee. Reads the legacy
   * app-registry.json (if present), writes each entry into the bee via
   * a single batch, renames the JSON to .bak so subsequent loads skip
   * it. Returns true if migrated, false if no JSON existed.
   */
  async _migrateJsonToBee () {
    if (!this._bee || !this._filePath) return false
    let raw
    try {
      raw = await readFile(this._filePath, 'utf8')
    } catch (_) {
      return false // no JSON to migrate
    }

    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (_) {
      // Corrupt JSON — bail rather than lose data. Operator can inspect
      // app-registry.json directly.
      this.emit('error', { context: 'migrate-parse', error: new Error('CORRUPT_REGISTRY_JSON') })
      return false
    }

    const entries = Array.isArray(parsed) ? parsed : Object.values(parsed)
    if (entries.length === 0) {
      // Empty registry file is still safe to migrate (no-op + rename).
      try { await rename(this._filePath, this._filePath + '.bak') } catch (_) {}
      return false
    }

    const batch = this._bee.batch()
    let written = 0
    for (const entry of entries) {
      const appKey = entry.appKey || entry.driveKey
      if (!appKey) continue
      await batch.put(appKey, entry)
      written++
    }
    await batch.flush()

    // Rename the JSON to .bak only after the bee batch flush succeeded.
    // If migration fails mid-flight, the next startup retries.
    try { await rename(this._filePath, this._filePath + '.bak') } catch (_) {}

    this.emit('migrated', { count: written, source: 'json', target: 'hyperbee' })
    return true
  }

  /**
   * Load registry from disk. Returns entries array for reseeding.
   *
   * v0.8.25: prefers Hyperbee if a Corestore was attached via setStore().
   * Falls back to legacy JSON-blob mode if no store is configured.
   */
  async load () {
    // Tombstones first: boot-replay must know what was deliberately shed.
    await this._loadEvicted()
    // v0.8.25 — try bee first
    const bee = await this._openBee()
    if (bee) {
      // First-time migration from legacy JSON (if it exists)
      await this._migrateJsonToBee()

      // Read all entries from the bee into the in-memory Map
      const entries = []
      try {
        for await (const node of bee.createReadStream()) {
          const entry = node.value
          if (!entry || typeof entry !== 'object') continue
          const appKey = node.key
          if (!appKey) continue
          this._hydrateEntry(appKey, entry)
          entries.push(this._reseedEntry(entry, appKey))
        }
      } catch (err) {
        // v0.8.28 (#28 follow-up): SESSION_CLOSED here means the bee's
        // underlying core was closed while we were reading — almost
        // always because node.stop() fired during start()'s
        // reseedFromRegistry hand-off. That's not a stale-ref bug; it's
        // a clean concurrent-shutdown signal. Quiet it so the
        // reliability-v2 multi-cycle test (and operators' logs) don't
        // flood with benign noise. Real errors (corruption, schema
        // drift, etc.) still surface via the 'error' event.
        const isShutdownRace =
          err && (
            err.code === 'SESSION_CLOSED' ||
            err.code === 'CORE_CLOSED' ||
            err.code === 'ERR_CLOSED' ||
            /closing|closed|destroyed/i.test(err.message || '')
          )
        if (!isShutdownRace) {
          this.emit('error', { context: 'load-bee', error: err })
        }
        return []
      }
      return entries.filter(e => e.appKey)
    }

    // Legacy JSON path — pre-v0.8.25 behavior, used when no store
    // attached (tests, headless usage).
    if (!this._filePath) return []

    try {
      const data = JSON.parse(await readFile(this._filePath, 'utf8'))

      // Support both array format (old seeded-apps.json) and object format
      const entries = Array.isArray(data) ? data : Object.values(data)

      // Populate in-memory state from disk via the shared helper.
      for (const entry of entries) {
        const appKey = entry.appKey || entry.driveKey
        if (!appKey) continue
        this._hydrateEntry(appKey, entry)
      }

      return entries
        .map(e => this._reseedEntry(e, e.appKey || e.driveKey))
        .filter(e => e.appKey)
    } catch (_) {
      return []
    }
  }

  /**
   * v0.8.25 — Hydrate the in-memory Map with an entry loaded from
   * persistence (bee or JSON). Shared between both paths so the
   * normalization rules live in one place.
   */
  _hydrateEntry (appKey, entry) {
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
      icon: entry.icon || null,
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
      publisherPubkey: entry.publisherPubkey || null,
      durability: Number.isFinite(entry.durability) ? entry.durability : 0,
      revocable: entry.revocable !== false,
      categories: entry.categories || null,
      bytesServed: 0,
      anchored: entry.anchored === true,
      anchoredAt: entry.anchoredAt || null,
      anchoredLength: typeof entry.anchoredLength === 'number' ? entry.anchoredLength : 0,
      lastAnchorCheck: entry.lastAnchorCheck || null,
      maxStorage: Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
        ? Math.floor(entry.maxStorage)
        : null,
      leaseManaged: entry.leaseManaged === true,
      // drive and discoveryKey are set during reseeding
      drive: null,
      discoveryKey: null
    })

    if (entry.appId && normalizeContentType(entry.type, 'app') === 'app') {
      this.byAppId.set(entry.appId, appKey)
    }
  }

  /**
   * v0.8.25 — Build the reseed-shape payload that reseedFromRegistry
   * passes back through seedApp. Shared between bee + JSON load paths.
   */
  _reseedEntry (e, appKey) {
    return {
      appKey: appKey || e.appKey || e.driveKey,
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
      publisherPubkey: e.publisherPubkey || null,
      durability: Number.isFinite(e.durability) ? e.durability : 0,
      revocable: e.revocable !== false,
      maxStorage: Number.isFinite(e.maxStorage) && e.maxStorage > 0
        ? Math.floor(e.maxStorage)
        : null,
      leaseManaged: e.leaseManaged === true
    }
  }

  /**
   * v0.8.25 — Build the persistable snapshot of an in-memory entry.
   * Used by both bee-mode (single put on every mutation) and legacy
   * JSON-mode (whole-file rewrite on debounced save).
   */
  _persistShape (appKey, entry) {
    return {
      appKey,
      appId: entry.appId || null,
      type: normalizeContentType(entry.type, 'app'),
      parentKey: entry.parentKey || null,
      mountPath: entry.mountPath || null,
      version: entry.version || null,
      name: entry.name || entry.appId || null,
      description: entry.description || '',
      author: entry.author || null,
      icon: entry.icon || null,
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
      publisherPubkey: entry.publisherPubkey || null,
      durability: Number.isFinite(entry.durability) ? entry.durability : 0,
      revocable: entry.revocable !== false,
      categories: entry.categories || null,
      startedAt: entry.startedAt || Date.now(),
      discoveryKey: entry.discoveryKey
        ? (typeof entry.discoveryKey === 'string' ? entry.discoveryKey : entry.discoveryKey.toString('hex'))
        : null,
      anchored: entry.anchored === true,
      anchoredAt: entry.anchoredAt || null,
      anchoredLength: entry.anchoredLength || 0,
      lastAnchorCheck: entry.lastAnchorCheck || null,
      maxStorage: Number.isFinite(entry.maxStorage) && entry.maxStorage > 0
        ? Math.floor(entry.maxStorage)
        : null,
      leaseManaged: entry.leaseManaged === true
    }
  }

  /**
   * Save registry to disk. Uses atomic write (write temp, rename).
   * Coalesces rapid writes — only one save happens at a time.
   */
  async save (opts = {}) {
    const throwOnError = opts.throwOnError === true

    // v0.8.25 — Bee mode: each mutation already wrote its own block via
    // _persistEntryToBee / _deleteEntryFromBee. save() is effectively a
    // no-op except for flushing the bee's internal write buffer.
    if (this._beeReady && this._bee) {
      try {
        if (typeof this._bee.feed?.update === 'function') {
          // Best-effort flush — hyperbee buffers internally; this is a
          // safety net for shutdown-time persistence guarantees.
        }
        return
      } catch (err) {
        this.emit('error', { context: 'save-bee', error: err })
        if (throwOnError) throw err
        return
      }
    }

    // Legacy JSON mode — keep pre-v0.8.25 whole-file rewrite behavior.
    if (!this._filePath) return

    if (this._saving) {
      this._savePending = true
      if (throwOnError) {
        const err = await new Promise(resolve => this._saveIdleWaiters.push(resolve))
        if (err) throw err
      }
      return
    }

    this._saving = true
    let lastError = null
    try {
      do {
        this._savePending = false
        const entries = []
        for (const [appKey, entry] of this.apps) {
          entries.push(this._persistShape(appKey, entry))
        }

        const tmpPath = this._filePath + '.tmp'
        try {
          await writeFile(tmpPath, JSON.stringify(entries, null, 2))
          await rename(tmpPath, this._filePath)
          lastError = null
        } catch (err) {
          lastError = err
          this.emit('error', { context: 'save', error: err })
        }
      } while (this._savePending)
    } finally {
      this._saving = false
      const waiters = this._saveIdleWaiters.splice(0)
      for (const resolve of waiters) resolve(lastError)
    }

    if (lastError && throwOnError) throw lastError
  }

  /**
   * Enqueue a bee write so it runs after all previously-enqueued writes.
   * Used by the v0.8.25 single-entry persistence path (bee mode), which
   * fires for every set/update/delete/setAnchored/clearAnchored — each
   * mutation writes one small block instead of triggering a debounced
   * rewrite of the whole registry. Serialization prevents the concurrent
   * read-modify-write race that silently drops entries. The returned
   * promise resolves when THIS write settles; it's tracked in
   * _pendingBeeOps so flush() can drain. Errors are surfaced via the
   * 'error' event and reject the returned promise so explicit persistence
   * callers can fail closed; background callers attach a catch.
   */
  _enqueueBeeWrite (run) {
    // Snapshot the entry value at enqueue time so a later mutation can't
    // change what this op writes once it's already in the queue.
    const op = this._beeWriteTail.then(run, run)
    this._beeWriteTail = op.catch(() => {})
    this._pendingBeeOps.add(op)
    op.then(
      () => this._pendingBeeOps.delete(op),
      () => this._pendingBeeOps.delete(op)
    )
    return op
  }

  async _persistEntryToBee (appKey) {
    if (!this._beeReady || !this._bee) return
    const entry = this.apps.get(appKey)
    if (!entry) return
    const shape = this._persistShape(appKey, entry)
    return this._enqueueBeeWrite(async () => {
      if (!this._beeReady || !this._bee) return
      try {
        await this._bee.put(appKey, shape)
      } catch (err) {
        this.emit('error', { context: 'persist-bee', appKey, error: err })
        throw err
      }
    })
  }

  async _deleteEntryFromBee (appKey) {
    if (!this._beeReady || !this._bee) return
    return this._enqueueBeeWrite(async () => {
      if (!this._beeReady || !this._bee) return
      try {
        await this._bee.del(appKey)
      } catch (err) {
        this.emit('error', { context: 'delete-bee', appKey, error: err })
        throw err
      }
    })
  }

  _clearSaveDebounce () {
    if (!this._saveDebounceTimer) return
    clearTimeout(this._saveDebounceTimer)
    this._saveDebounceTimer = null
  }

  async persistEntry (appKey, opts = {}) {
    const throwOnError = opts.throwOnError === true
    try {
      if (this._beeReady) {
        await this._persistEntryToBee(appKey)
        return
      }
      this._clearSaveDebounce()
      await this.save({ throwOnError: true })
    } catch (err) {
      if (throwOnError) throw err
    }
  }

  async persistDelete (appKey, opts = {}) {
    const throwOnError = opts.throwOnError === true
    try {
      if (this._beeReady) {
        await this._deleteEntryFromBee(appKey)
        return
      }
      this._clearSaveDebounce()
      await this.save({ throwOnError: true })
    } catch (err) {
      if (throwOnError) throw err
    }
  }

  /**
   * v0.8.25 — schedule persistence for a single entry.
   * In bee mode, writes the one entry immediately (fire-and-forget).
   * In legacy mode, schedules a debounced whole-file write of all entries.
   *
   * @param {string} [appKey] - the entry that changed (required for bee mode)
   * @param {object} [opts]
   * @param {boolean} [opts.deleted] - if true, deletes from bee instead of putting
   */
  _scheduleSave (appKey, opts = {}) {
    if (this._beeReady) {
      // Bee mode — single-entry write or delete, fire-and-forget.
      // Errors surface via the 'error' event, don't block the caller.
      if (opts.deleted) {
        this._deleteEntryFromBee(appKey).catch(() => {})
      } else if (appKey) {
        this._persistEntryToBee(appKey).catch(() => {})
      }
      return
    }
    // Legacy JSON mode — debounced whole-file rewrite.
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
  async flush (opts = {}) {
    const throwOnError = opts.throwOnError === true
    this._clearSaveDebounce()
    // v0.8.25 — drain any fire-and-forget bee writes before returning.
    // Without this, shutdown can race the bee.put for a final
    // setAnchored() that we want to persist before close.
    let firstError = null
    if (this._pendingBeeOps && this._pendingBeeOps.size > 0) {
      const results = await Promise.allSettled([...this._pendingBeeOps])
      const failed = results.find(result => result.status === 'rejected')
      if (failed) firstError = failed.reason
    }
    try {
      await this.save({ throwOnError })
    } catch (err) {
      if (!firstError) firstError = err
    }
    if (firstError && throwOnError) throw firstError
  }
}
