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
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES } from '../config/storage-admission-authority.js'
import {
  compareVersions,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizeStorageClass
} from './constants.js'

const REGISTRY_FILE = 'app-registry.json'
const BEE_CORE_NAME = 'app-registry-v1'
const APP_REGISTRY_JOURNAL_AUTHORITY_KEY = 'workload:app-registry'
// Normal mutations may consume at most 48 KiB of the drive's 64 KiB registry
// allowance. The final 16 KiB is reserved for one measured retirement
// tombstone, so capacity exhaustion can never force an unbounded bee.del() or
// let delete/re-adopt reset append-only history.
const APP_REGISTRY_RETIREMENT_RESERVE_BYTES = 16 * 1024
const APP_REGISTRY_ACTIVE_METADATA_BUDGET_BYTES =
  STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES - APP_REGISTRY_RETIREMENT_RESERVE_BYTES
const APP_REGISTRY_LEGACY_ROW_PREFLIGHT_MARGIN_BYTES = 1024
const APP_REGISTRY_BEE_HEADER_MAX_BYTES = 1024
const APP_REGISTRY_PLAN_MAX_ATTEMPTS = 8
const CANONICAL_APP_KEY = /^[0-9a-f]{64}$/
const RUNTIME_APP_KEY = /^[0-9a-f]{64}$/i

function canonicalRuntimeAppKey (appKey) {
  return typeof appKey === 'string' && RUNTIME_APP_KEY.test(appKey)
    ? appKey.toLowerCase()
    : null
}

function registryInventoryError (reason, cause = null) {
  const err = new Error('APP_REGISTRY_INVENTORY_FAILED: ' + reason)
  err.code = 'APP_REGISTRY_INVENTORY_FAILED'
  err.reason = reason
  if (cause) err.cause = cause
  return err
}

function migrationDigest (raw) {
  const digest = b4a.alloc(32)
  sodium.crypto_generichash(digest, b4a.from(raw))
  return b4a.toString(digest, 'hex')
}

function safeCoreMetric (core, field) {
  const value = core?.[field]
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function sumBlockBytes (blocks) {
  let total = 0
  for (const block of blocks || []) {
    const bytes = b4a.isBuffer(block) ? block.byteLength : null
    if (!Number.isSafeInteger(bytes) || bytes < 0 || !Number.isSafeInteger(total + bytes)) return null
    total += bytes
  }
  return total
}

function validatedLegacyEntries (parsed) {
  if (!parsed || typeof parsed !== 'object') throw registryInventoryError('unsupported-json-shape')
  const entries = Array.isArray(parsed) ? parsed : Object.values(parsed)
  const seen = new Set()
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw registryInventoryError('invalid-entry')
    }
    const appKey = entry.appKey || entry.driveKey
    if (typeof appKey !== 'string' || !CANONICAL_APP_KEY.test(appKey)) throw registryInventoryError('invalid-app-key')
    if (entry.appKey != null && entry.appKey !== appKey) throw registryInventoryError('app-key-mismatch')
    if (entry.driveKey != null && entry.driveKey !== appKey) throw registryInventoryError('app-key-mismatch')
    validatePersistedStorageBound(entry)
    validatePersistedStorageProof(entry)
    validatePersistedMetadataBudget(entry)
    if (b4a.byteLength(JSON.stringify(entry)) + APP_REGISTRY_LEGACY_ROW_PREFLIGHT_MARGIN_BYTES >
        STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES) {
      throw registryInventoryError('storage-metadata-row-exceeds-commitment')
    }
    if (seen.has(appKey)) throw registryInventoryError('duplicate-app-key')
    seen.add(appKey)
  }
  return entries
}

function validatePersistedStorageBound (entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, 'maxStorage') || entry.maxStorage == null) return
  if (!Number.isSafeInteger(entry.maxStorage) || entry.maxStorage <= 0) {
    throw registryInventoryError('invalid-max-storage')
  }
}

function validatePersistedMetadataBudget (entry) {
  const hasBytes = entry.storageMetadataBytesWritten != null
  const hasRevision = entry.storageMetadataRevision != null
  if (!hasBytes && !hasRevision) return { bytes: 0, revision: 0 }
  if (!hasBytes || !hasRevision ||
      !Number.isSafeInteger(entry.storageMetadataBytesWritten) || entry.storageMetadataBytesWritten < 0 ||
      entry.storageMetadataBytesWritten > STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES ||
      !Number.isSafeInteger(entry.storageMetadataRevision) || entry.storageMetadataRevision < 0) {
    throw registryInventoryError('invalid-storage-metadata-budget')
  }
  return { bytes: entry.storageMetadataBytesWritten, revision: entry.storageMetadataRevision }
}

const STORAGE_PROOF_FIELDS = [
  'storageProvedDriveVersion',
  'storageProvedMetaLength',
  'storageProvedBlobLength',
  'storageProvedTotalBytes',
  'storageProvedMetaFork',
  'storageProvedBlobFork'
]

function validatePersistedStorageProof (entry) {
  const present = STORAGE_PROOF_FIELDS.filter(field => entry[field] != null)
  if (present.length === 0) return false
  if (present.length !== STORAGE_PROOF_FIELDS.length || entry.anchored !== true ||
      !Number.isSafeInteger(entry.storageProvedDriveVersion) || entry.storageProvedDriveVersion <= 0 ||
      !Number.isSafeInteger(entry.storageProvedMetaLength) || entry.storageProvedMetaLength < 0 ||
      !Number.isSafeInteger(entry.storageProvedBlobLength) || entry.storageProvedBlobLength < 0 ||
      !Number.isSafeInteger(entry.storageProvedTotalBytes) || entry.storageProvedTotalBytes < 0 ||
      !Number.isSafeInteger(entry.storageProvedMetaFork) || entry.storageProvedMetaFork < 0 ||
      !Number.isSafeInteger(entry.storageProvedBlobFork) || entry.storageProvedBlobFork < 0 ||
      entry.anchoredLength !== entry.storageProvedDriveVersion ||
      !Number.isSafeInteger(entry.maxStorage) || entry.maxStorage <= 0 ||
      entry.storageProvedTotalBytes > entry.maxStorage) {
    throw registryInventoryError('invalid-storage-proof-tuple')
  }
  return true
}
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
    this._persistenceMode = opts.store ? 'bee' : 'json'
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
    this._metadataBudgets = new Map()
    this._metadataTombstones = new Set()
    this._metadataTombstoneEntries = new Map()
    this._durableEntries = new Map()
    this._entryGenerations = new Map()
    this._registryJournal = null
    this.storageAdmission = opts.storageAdmission || null
    this._requirePhysicalEnforcement = opts.requirePhysicalEnforcement === true ||
      (opts.requirePhysicalEnforcement !== false && !!opts.storageAdmission)
    this._physicalReadOnly = false

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
    // Bee mode persists these as measured storageDeleted rows in the same
    // append-only registry journal. The JSON sidecar remains only for the
    // legacy no-Corestore mode and is migrated on the first Bee startup.
    this.evicted = new Map()
    this._evictedPath = storagePath ? join(storagePath, EVICTED_FILE) : null
    this._evictedPersistTail = Promise.resolve()
  }

  setStorageAdmission (storageAdmission, opts = {}) {
    this.storageAdmission = storageAdmission || null
    if (Object.prototype.hasOwnProperty.call(opts, 'requirePhysicalEnforcement')) {
      this._requirePhysicalEnforcement = opts.requirePhysicalEnforcement === true
    } else if (this.storageAdmission) {
      this._requirePhysicalEnforcement = true
    }
  }

  _physicalEnforcementRequired () {
    return this._requirePhysicalEnforcement === true
  }

  get physicalReadOnly () {
    return this._physicalReadOnly === true || !this._physicalWritesAvailable()
  }

  _physicalWritesAvailable () {
    if (!this._physicalEnforcementRequired()) return true
    if (!this.storageAdmission) return false
    if (this.storageAdmission.physicalEnforcementActive !== true) return false
    if (typeof this.storageAdmission.mutationAdmission === 'function' &&
        this.storageAdmission.mutationAdmission().allowed !== true) return false
    const attestation = typeof this.storageAdmission.physicalEnforcementSnapshot === 'function'
      ? this.storageAdmission.physicalEnforcementSnapshot()
      : null
    return !!attestation && Number.isSafeInteger(attestation.usedAllocatedBytes) &&
      Number.isSafeInteger(attestation.hardLimitBytes) &&
      attestation.usedAllocatedBytes < attestation.hardLimitBytes
  }

  _physicalWriteError (cause = null) {
    const err = new Error('APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
    err.code = 'APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE'
    if (cause) err.cause = cause
    return err
  }

  _assertPhysicalWritesAvailable () {
    if (this._physicalReadOnly || !this._physicalWritesAvailable()) throw this._physicalWriteError()
  }

  assertDurableWritesAvailable () {
    this._assertPhysicalWritesAvailable()
    return true
  }

  async _runPhysicalWrite (purpose, phase, run) {
    this._assertPhysicalWritesAvailable()
    if (!this._physicalEnforcementRequired()) return run()
    try {
      return await this.storageAdmission.runPhysicalMutation({ purpose, phase }, run)
    } catch (err) {
      if (err?.code === 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE') {
        throw this._physicalWriteError(err)
      }
      throw err
    }
  }

  // ─── Eviction tombstones ──────────────────────────────────────────

  markEvicted (appKeyHex, at = Date.now()) {
    appKeyHex = canonicalRuntimeAppKey(appKeyHex)
    if (appKeyHex === null) throw new Error('Invalid app key: must be 64 hex characters')
    if (!Number.isSafeInteger(at) || at <= 0) throw new Error('Invalid eviction timestamp')
    this._assertPhysicalWritesAvailable()
    if (this._beeReady) {
      if (this.apps.has(appKeyHex)) {
        return Promise.reject(new Error('APP_REGISTRY_EVICTION_REQUIRES_DURABLE_DELETE'))
      }
      const current = this._metadataTombstoneEntries.get(appKeyHex)
      if (current?.evictedAt === at) {
        this.evicted.set(appKeyHex, at)
        return Promise.resolve(true)
      }
      return this._deleteEntryFromBee(appKeyHex, { strict: true, evictedAt: at }).then(() => true)
    }
    this.evicted.set(appKeyHex, at)
    // Bound the set: oldest tombstones fall off — by then the entry is
    // either long gone network-wide or legitimately re-adoptable.
    if (this.evicted.size > MAX_TOMBSTONES) {
      const oldest = [...this.evicted.entries()].sort((a, b) => a[1] - b[1])
      for (let i = 0; i < oldest.length - MAX_TOMBSTONES; i++) this.evicted.delete(oldest[i][0])
    }
    return this._persistEvicted()
  }

  isEvicted (appKeyHex) {
    appKeyHex = canonicalRuntimeAppKey(appKeyHex)
    if (appKeyHex === null) return false
    return this.evicted.has(appKeyHex)
  }

  clearEvicted (appKeyHex) {
    appKeyHex = canonicalRuntimeAppKey(appKeyHex)
    if (appKeyHex === null) return Promise.resolve(false)
    if (!this.evicted.has(appKeyHex)) return Promise.resolve(false)
    this._assertPhysicalWritesAvailable()
    if (this._beeReady) {
      return this._deleteEntryFromBee(appKeyHex, { strict: true, evictedAt: null }).then(() => true)
    }
    this.evicted.delete(appKeyHex)
    return Promise.resolve(this._persistEvicted()).then(() => true)
  }

  _persistEvicted () {
    if (!this._evictedPath) return
    const operation = this._evictedPersistTail
      .catch(() => {})
      .then(() => this._writeEvicted())
    this._evictedPersistTail = operation.catch(() => {})
    return operation
  }

  async _writeEvicted () {
    const tmp = this._evictedPath + '.tmp'
    try {
      await this._runPhysicalWrite('app-registry-evicted-json', 'runtime', async () => {
        await writeFile(tmp, JSON.stringify(Object.fromEntries(this.evicted)))
        await rename(tmp, this._evictedPath)
      })
    } catch (err) {
      try { await unlink(tmp) } catch {}
      this._emitSafely('error', { context: 'persist-evicted', error: err })
      throw err
    }
  }

  async _loadEvicted (opts = {}) {
    if (!this._evictedPath) return
    const strict = opts.strict === true
    let raw
    try {
      raw = await readFile(this._evictedPath, 'utf8')
    } catch (err) {
      if (err?.code === 'ENOENT') {
        this.evicted.clear()
        return
      }
      if (strict) throw registryInventoryError('evicted-read-failed', err)
      this.evicted.clear()
      return
    }
    let data
    try {
      data = JSON.parse(raw)
    } catch (err) {
      if (strict) throw registryInventoryError('evicted-json-corrupt', err)
      this.evicted.clear()
      return
    }
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        Object.keys(data).length > MAX_TOMBSTONES) {
      if (strict) throw registryInventoryError('evicted-shape-invalid')
      this.evicted.clear()
      return
    }
    const validated = new Map()
    for (const [key, value] of Object.entries(data)) {
      if (!CANONICAL_APP_KEY.test(key) || !Number.isSafeInteger(value) || value <= 0) {
        if (strict) throw registryInventoryError('evicted-row-invalid')
        continue
      }
      validated.set(key, value)
    }
    if (strict && validated.size !== Object.keys(data).length) {
      throw registryInventoryError('evicted-row-invalid')
    }
    this.evicted.clear()
    for (const [key, value] of validated) this.evicted.set(key, value)
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
    this._persistenceMode = 'bee'
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
    this._registryJournal = null
  }

  // ─── Queries ───────────────────────────────────────────────

  get size () { return this.apps.size }

  has (appKey) {
    appKey = canonicalRuntimeAppKey(appKey)
    return appKey !== null && this.apps.has(appKey)
  }

  get (appKey) {
    appKey = canonicalRuntimeAppKey(appKey)
    return appKey === null ? undefined : this.apps.get(appKey)
  }

  getByAppId (appId) {
    const appKey = this.byAppId.get(appId)
    return appKey ? this.apps.get(appKey) : null
  }

  keys () { return this.apps.keys() }

  values () { return this.apps.values() }

  entries () { return this.apps.entries() }

  [Symbol.iterator] () { return this.apps[Symbol.iterator]() }

  /**
   * Attach process-local serving handles to an already validated durable row.
   * This cannot create a row or alter durable metadata, so serve-only recovery
   * can reopen existing content without bypassing the physical write gate.
   */
  attachRuntime (appKey, refs = {}) {
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry || !refs || typeof refs !== 'object' || Array.isArray(refs)) return false
    const allowed = new Set([
      'drive',
      'discoveryKey',
      'discoveryHandles',
      'downloadRanges',
      'downloadSnapshotCores',
      'downloadRegistration',
      'bytesServed',
      'retiring'
    ])
    for (const key of Object.keys(refs)) {
      if (!allowed.has(key)) throw new Error('APP_REGISTRY_RUNTIME_FIELD_INVALID: ' + key)
    }
    Object.assign(entry, refs)
    this._emitSafely('runtime', { type: 'attach', appKey, fields: Object.keys(refs) })
    return true
  }

  snapshot () {
    return {
      apps: new Map(this.apps),
      byAppId: new Map(this.byAppId),
      evicted: new Map(this.evicted),
      metadataBudgets: new Map(this._metadataBudgets),
      metadataTombstones: new Set(this._metadataTombstones),
      metadataTombstoneEntries: new Map(this._metadataTombstoneEntries),
      durableEntries: new Map(this._durableEntries),
      entryGenerations: new Map(this._entryGenerations)
    }
  }

  restoreSnapshot (snapshot = {}) {
    this.apps.clear()
    this.byAppId.clear()
    this.evicted.clear()
    this._metadataBudgets.clear()
    this._metadataTombstones.clear()
    this._metadataTombstoneEntries.clear()
    this._durableEntries.clear()
    this._entryGenerations.clear()
    for (const [key, value] of snapshot.apps || []) this.apps.set(key, value)
    for (const [key, value] of snapshot.byAppId || []) this.byAppId.set(key, value)
    for (const [key, value] of snapshot.evicted || []) this.evicted.set(key, value)
    for (const [key, value] of snapshot.metadataBudgets || []) this._metadataBudgets.set(key, value)
    for (const key of snapshot.metadataTombstones || []) this._metadataTombstones.add(key)
    for (const [key, value] of snapshot.metadataTombstoneEntries || []) this._metadataTombstoneEntries.set(key, value)
    for (const [key, value] of snapshot.durableEntries || []) this._durableEntries.set(key, value)
    for (const [key, value] of snapshot.entryGenerations || []) this._entryGenerations.set(key, value)
  }

  // ─── Mutations ─────────────────────────────────────────────

  // Registry observers are telemetry, never transaction participants. Invoke
  // each listener independently so one throwing observer cannot interrupt a
  // durable mutation, skip later observers, or manufacture a false ACK path.
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

  _isAppType (entry) {
    return normalizeContentType(entry?.type, 'app') === 'app'
  }

  _isAppIdIndexed (entry) {
    return this._isAppType(entry) && typeof entry?.appId === 'string' && entry.appId.length > 0
  }

  _advanceEntryGeneration (appKey) {
    const next = (this._entryGenerations.get(appKey) || 0) + 1
    if (!Number.isSafeInteger(next)) throw new Error('APP_REGISTRY_ENTRY_GENERATION_OVERFLOW')
    this._entryGenerations.set(appKey, next)
    return next
  }

  _restoreDurableEntry (appKey, generation) {
    if (this._entryGenerations.get(appKey) !== generation) return false
    const current = this.apps.get(appKey)
    if (this._isAppIdIndexed(current) && this.byAppId.get(current.appId) === appKey) {
      this.byAppId.delete(current.appId)
    }
    const durable = this._durableEntries.get(appKey)
    if (!durable) {
      this.apps.delete(appKey)
      return true
    }
    const restored = this._normalizeEntry({ ...durable })
    this.apps.set(appKey, restored)
    if (this._isAppIdIndexed(restored)) this.byAppId.set(restored.appId, appKey)
    return true
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
    const storageProvedDriveVersion = Number.isSafeInteger(entry.storageProvedDriveVersion) && entry.storageProvedDriveVersion > 0 ? entry.storageProvedDriveVersion : null
    const storageProvedMetaLength = Number.isSafeInteger(entry.storageProvedMetaLength) && entry.storageProvedMetaLength >= 0 ? entry.storageProvedMetaLength : null
    const storageProvedBlobLength = Number.isSafeInteger(entry.storageProvedBlobLength) && entry.storageProvedBlobLength >= 0 ? entry.storageProvedBlobLength : null
    const storageProvedTotalBytes = Number.isSafeInteger(entry.storageProvedTotalBytes) && entry.storageProvedTotalBytes >= 0 ? entry.storageProvedTotalBytes : null
    const storageProvedMetaFork = Number.isSafeInteger(entry.storageProvedMetaFork) && entry.storageProvedMetaFork >= 0 ? entry.storageProvedMetaFork : null
    const storageProvedBlobFork = Number.isSafeInteger(entry.storageProvedBlobFork) && entry.storageProvedBlobFork >= 0 ? entry.storageProvedBlobFork : null
    const storageMetadataBytesWritten = Number.isSafeInteger(entry.storageMetadataBytesWritten) && entry.storageMetadataBytesWritten >= 0
      ? entry.storageMetadataBytesWritten
      : 0
    const storageMetadataRevision = Number.isSafeInteger(entry.storageMetadataRevision) && entry.storageMetadataRevision >= 0
      ? entry.storageMetadataRevision
      : 0

    // v0.8.12: per-app maxStorage from the seed request. Persisted so we
    // can compare on re-pin (cap-up vs cap-down vs unchanged) instead of
    // forgetting it between restarts. See AppLifecycle._reconcileSeedOptsOnRepin.
    const maxStorage = Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
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
      storageProvedDriveVersion,
      storageProvedMetaLength,
      storageProvedBlobLength,
      storageProvedTotalBytes,
      storageProvedMetaFork,
      storageProvedBlobFork,
      storageMetadataBytesWritten,
      storageMetadataRevision,
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
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) throw new Error('Invalid app key: must be 64 hex characters')
    this._assertPhysicalWritesAvailable()
    const trackedBudget = this._metadataBudgets.get(appKey)
    const normalized = this._normalizeEntry(trackedBudget
      ? {
          ...entry,
          storageMetadataBytesWritten: entry.storageMetadataBytesWritten ?? trackedBudget.bytes,
          storageMetadataRevision: entry.storageMetadataRevision ?? trackedBudget.revision
        }
      : entry)
    this._advanceEntryGeneration(appKey)
    this.apps.set(appKey, normalized)

    // Update dedup index if entry has an appId
    if (this._isAppIdIndexed(normalized)) {
      this.byAppId.set(normalized.appId, appKey)
    }

    if (opts.persist !== false) this._scheduleSave(appKey)
    this._emitSafely('change', { type: 'set', appKey, entry: normalized })
  }

  /**
   * Update metadata on an existing entry without replacing it.
   */
  update (appKey, updates, opts = {}) {
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry) return false
    this._assertPhysicalWritesAvailable()
    this._advanceEntryGeneration(appKey)

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
    this._emitSafely('change', { type: 'update', appKey, entry })
    return true
  }

  /**
   * Remove a seeded app. Automatically persists and emits change event.
   */
  delete (appKey, opts = {}) {
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry) return false
    this._assertPhysicalWritesAvailable()
    this._advanceEntryGeneration(appKey)

    // Clean dedup index
    if (this._isAppIdIndexed(entry) && this.byAppId.get(entry.appId) === appKey) {
      this.byAppId.delete(entry.appId)
    }

    this.apps.delete(appKey)
    if (opts.persist !== false) this._scheduleSave(appKey, { deleted: true })
    this._emitSafely('change', { type: 'delete', appKey })
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
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry) return false
    this._assertPhysicalWritesAvailable()

    this._advanceEntryGeneration(appKey)
    const wasAnchored = entry.anchored === true
    const now = Date.now()
    entry.anchored = true
    entry.anchoredLength = Math.max(entry.anchoredLength || 0, length || 0)
    entry.lastAnchorCheck = now
    if (!wasAnchored) entry.anchoredAt = now

    this._scheduleSave(appKey)
    if (!wasAnchored) {
      this._emitSafely('change', { type: 'anchored', appKey, entry })
    } else {
      this._emitSafely('change', { type: 'anchor-update', appKey, entry })
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
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry) return false
    if (entry.anchored !== true) return false
    this._assertPhysicalWritesAvailable()
    this._advanceEntryGeneration(appKey)
    entry.anchored = false
    entry.anchoredLength = 0
    entry.storageProvedDriveVersion = null
    entry.storageProvedMetaLength = null
    entry.storageProvedBlobLength = null
    entry.storageProvedTotalBytes = null
    entry.storageProvedMetaFork = null
    entry.storageProvedBlobFork = null
    entry.lastAnchorCheck = Date.now()
    this._scheduleSave(appKey)
    this._emitSafely('change', { type: 'unanchored', appKey, entry, reason })
    return true
  }

  /**
   * Update lastAnchorCheck without changing anchored state — useful when
   * we did a check, found no blocks, and want to record that we tried.
   */
  recordAnchorCheck (appKey) {
    appKey = canonicalRuntimeAppKey(appKey)
    if (appKey === null) return false
    const entry = this.apps.get(appKey)
    if (!entry) return false
    entry.lastAnchorCheck = Date.now()
    // Health cadence is telemetry, not durable state. Persisting every
    // periodic check would append unbounded Hyperbee history beneath a fixed
    // per-pin metadata allowance. The timestamp is included opportunistically
    // with the next real bounded state transition.
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
        // Public capacity commitment from the signed seed request. This is not
        // inspected content metadata, so blind/redacted rows retain it; peers
        // need the finite bound to make their own admission decision.
        maxStorageBytes: Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
          ? entry.maxStorage
          : null,
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
        maxStorageBytes: Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
          ? entry.maxStorage
          : null,
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
      this._bee = null
      this._beeReady = false
      throw registryInventoryError('bee-open-failed', err)
    }
  }

  async _ensureBeeHeader () {
    const core = this._bee?.core || this._bee?.feed
    const beforeLength = safeCoreMetric(core, 'length')
    const beforeBytes = safeCoreMetric(core, 'byteLength')
    if (beforeLength === null || beforeBytes === null) {
      throw registryInventoryError('bee-journal-measurement-unavailable')
    }
    if (beforeLength !== 0) return

    const batch = this._bee.batch()
    try {
      if (!batch || typeof batch.getRoot !== 'function') {
        throw registryInventoryError('bee-journal-planning-unavailable')
      }
      // Hyperbee 2.27.x lazily appends its protocol header from getRoot(true).
      // Materialize that one-time fixed record before establishing the journal
      // baseline; every later mutation is planned and settled byte-for-byte.
      await this._runPhysicalWrite(
        'app-registry-bee-header',
        'recovery',
        () => batch.getRoot(true)
      )
    } finally {
      if (batch && typeof batch.close === 'function') await batch.close()
    }

    const afterLength = safeCoreMetric(core, 'length')
    const afterBytes = safeCoreMetric(core, 'byteLength')
    const headerBytes = afterBytes === null ? null : afterBytes - beforeBytes
    if (afterLength !== 1 || headerBytes === null || headerBytes <= 0 ||
        headerBytes > APP_REGISTRY_BEE_HEADER_MAX_BYTES) {
      throw registryInventoryError('bee-header-settlement-invalid')
    }
  }

  async _readBeeInventory () {
    const inventory = []
    const seen = new Set()
    for await (const node of this._bee.createReadStream()) {
      const entry = node.value
      const appKey = node.key
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
          typeof appKey !== 'string' || !CANONICAL_APP_KEY.test(appKey) ||
          (entry.appKey != null && entry.appKey !== appKey) ||
          (entry.driveKey != null && entry.driveKey !== appKey) || seen.has(appKey)) {
        throw registryInventoryError('bee-row-invalid')
      }
      const metadataBudget = validatePersistedMetadataBudget(entry)
      const tombstone = entry.storageDeleted === true
      if (tombstone) {
        if (metadataBudget.bytes <= 0 || metadataBudget.revision <= 0 ||
            STORAGE_PROOF_FIELDS.some(field => entry[field] != null)) {
          throw registryInventoryError('bee-tombstone-invalid')
        }
      } else {
        validatePersistedStorageBound(entry)
        validatePersistedStorageProof(entry)
      }
      seen.add(appKey)
      inventory.push({ appKey, entry, metadataBudget, tombstone })
    }
    return inventory
  }

  _recoverRegistryJournal (inventory) {
    const core = this._bee?.core || this._bee?.feed
    const byteLength = safeCoreMetric(core, 'byteLength')
    const length = safeCoreMetric(core, 'length')
    const fork = safeCoreMetric(core, 'fork')
    if (byteLength === null || length === null || fork === null) {
      throw registryInventoryError('bee-journal-measurement-unavailable')
    }

    this._metadataBudgets.clear()
    this._metadataTombstones.clear()
    this._metadataTombstoneEntries.clear()
    this.evicted.clear()
    let chargedBytes = 0
    for (const row of inventory) {
      if (!Number.isSafeInteger(chargedBytes + row.metadataBudget.bytes)) {
        throw registryInventoryError('bee-journal-budget-overflow')
      }
      chargedBytes += row.metadataBudget.bytes
      this._metadataBudgets.set(row.appKey, row.metadataBudget)
      if (row.tombstone) {
        this._metadataTombstones.add(row.appKey)
        this._metadataTombstoneEntries.set(row.appKey, row.entry)
        if (Number.isSafeInteger(row.entry.evictedAt) && row.entry.evictedAt > 0) {
          this.evicted.set(row.appKey, row.entry.evictedAt)
        }
      }
    }
    if (chargedBytes > byteLength) {
      throw registryInventoryError('bee-journal-budget-exceeds-feed')
    }

    const baselineBytes = byteLength - chargedBytes
    const capacityBytes = baselineBytes +
      inventory.length * STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES
    if (!Number.isSafeInteger(capacityBytes) || capacityBytes < byteLength) {
      throw registryInventoryError('bee-journal-capacity-invalid')
    }
    this._registryJournal = {
      baselineBytes,
      chargedBytes,
      distinctKeys: inventory.length,
      expectedByteLength: byteLength,
      expectedLength: length,
      expectedFork: fork,
      reservedBytes: 0
    }

    if (this.storageAdmission && inventory.length > 0) {
      const record = this.storageAdmission.adoptRecovery(
        APP_REGISTRY_JOURNAL_AUTHORITY_KEY,
        capacityBytes,
        { kind: 'workload', metadataOverheadBytes: 0, actualBytes: byteLength }
      )
      if (!record || !this.storageAdmission.reconcileActual(
        APP_REGISTRY_JOURNAL_AUTHORITY_KEY,
        byteLength
      )) {
        throw registryInventoryError('bee-journal-authority-recovery-failed')
      }
    }
  }

  async _migrateEvictedSidecarToBee (inventoryByKey) {
    if (!this._bee || !this._evictedPath) return false
    let raw
    try {
      raw = await readFile(this._evictedPath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return false
      throw registryInventoryError('evicted-migration-read-failed', err)
    }

    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (err) {
      throw registryInventoryError('evicted-migration-json-corrupt', err)
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw registryInventoryError('evicted-migration-shape-invalid')
    }
    const entries = Object.entries(parsed)
    if (entries.length > MAX_TOMBSTONES) {
      throw registryInventoryError('evicted-migration-count-invalid')
    }

    const items = []
    for (const [appKey, evictedAt] of entries) {
      if (!CANONICAL_APP_KEY.test(appKey) || !Number.isSafeInteger(evictedAt) || evictedAt <= 0) {
        throw registryInventoryError('evicted-migration-row-invalid')
      }
      const current = inventoryByKey.get(appKey)
      if (current && !current.tombstone) {
        throw registryInventoryError('evicted-migration-active-row-conflict')
      }
      if (current?.entry?.evictedAt === evictedAt) continue
      items.push({
        appKey,
        shape: { appKey, evictedAt },
        priorBudget: this._metadataBudgets.get(appKey) || { bytes: 0, revision: 0 },
        tombstone: true
      })
    }
    if (items.length > 0) {
      await this._runRegistryJournalMutation(() => this._appendMeasuredBeeShapes(items, { recovery: true }))
    }
    try {
      await this._runPhysicalWrite(
        'app-registry-evicted-migration-rename',
        'recovery',
        () => rename(this._evictedPath, this._evictedPath + '.bak')
      )
    } catch (err) {
      throw registryInventoryError('evicted-migration-rename-failed', err)
    }
    this._emitSafely('migrated', { count: items.length, source: 'evicted-json', target: 'hyperbee' })
    return true
  }

  /**
   * One-time JSON-to-bee migration. The whole batch goes through the same
   * measured journal planner as runtime puts. A digest marker makes the
   * post-flush/pre-rename crash window idempotent without resetting debt.
   */
  async _migrateJsonToBee (inventoryByKey) {
    if (!this._bee || !this._filePath) return false
    let raw
    try {
      raw = await readFile(this._filePath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return false
      throw registryInventoryError('migration-read-failed', err)
    }

    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (err) {
      throw registryInventoryError('migration-json-corrupt', err)
    }

    const entries = validatedLegacyEntries(parsed)
    if (entries.length === 0) {
      // Empty registry file is still safe to migrate (no-op + rename).
      try {
        await this._runPhysicalWrite(
          'app-registry-json-empty-migration-rename',
          'recovery',
          () => rename(this._filePath, this._filePath + '.bak')
        )
      } catch (err) {
        throw registryInventoryError('migration-rename-failed', err)
      }
      return true
    }

    const digest = migrationDigest(raw)
    const items = []
    for (const entry of entries) {
      const appKey = entry.appKey || entry.driveKey
      if (!appKey) continue
      const current = inventoryByKey.get(appKey)
      // An eviction tombstone is authoritative over a stale legacy registry
      // row. Replaying that JSON row would immediately undo the deliberate
      // shed during the same startup that migrated the tombstone.
      if (current?.tombstone && Number.isSafeInteger(current.entry.evictedAt) && current.entry.evictedAt > 0) {
        continue
      }
      if (current?.entry?.storageMigrationDigest === digest) continue
      if (this.storageAdmission) {
        this.storageAdmission.adoptRecovery(`drive:${appKey}`, entry.maxStorage, { kind: 'drive' })
      }
      items.push({
        appKey,
        shape: {
          ...entry,
          storageMigrationDigest: digest,
          storageMetadataRevision: 0,
          storageMetadataBytesWritten: 0
        },
        priorBudget: this._metadataBudgets.get(appKey) || { bytes: 0, revision: 0 },
        tombstone: false
      })
    }
    if (items.length > 0) {
      await this._runRegistryJournalMutation(() => this._appendMeasuredBeeShapes(items, { recovery: true }))
    }

    // Rename the JSON to .bak only after the bee batch flush succeeded.
    // A rename failure blocks startup; the digest above makes retry a no-op.
    try {
      await this._runPhysicalWrite(
        'app-registry-json-migration-rename',
        'recovery',
        () => rename(this._filePath, this._filePath + '.bak')
      )
    } catch (err) {
      throw registryInventoryError('migration-rename-failed', err)
    }

    this._emitSafely('migrated', { count: items.length, source: 'json', target: 'hyperbee' })
    return true
  }

  /**
   * Load registry from disk. Returns entries array for reseeding.
   *
   * v0.8.25: prefers Hyperbee if a Corestore was attached via setStore().
   * Falls back to legacy JSON-blob mode if no store is configured.
   */
  async load () {
    this._physicalReadOnly = this._physicalEnforcementRequired() && !this._physicalWritesAvailable()
    // v0.8.25 — try bee first
    const bee = await this._openBee()
    if (bee) {
      try {
        const core = bee.core || bee.feed
        const existingLength = safeCoreMetric(core, 'length')
        if (this._physicalReadOnly) {
          // Opening an empty Bee must not materialize its protocol header
          // without a backend hard-allocation enforcer. A validated legacy
          // inventory may still hydrate read-only; otherwise start empty.
          if (existingLength === 0) return this._loadLegacyJsonReadOnly()
          if (existingLength === null) throw registryInventoryError('bee-journal-measurement-unavailable')
          const inventory = await this._readBeeInventory()
          this._recoverRegistryJournal(inventory)
          if (inventory.length === 0) return this._loadLegacyJsonReadOnly()
          this.apps.clear()
          this.byAppId.clear()
          this._durableEntries.clear()
          this._entryGenerations.clear()
          const entries = []
          for (const { appKey, entry, tombstone } of inventory) {
            if (tombstone) continue
            this._hydrateEntry(appKey, entry)
            entries.push(this._reseedEntry(entry, appKey))
          }
          return entries.filter(entry => entry.appKey)
        }
        await this._ensureBeeHeader()
        let inventory = await this._readBeeInventory()
        this._recoverRegistryJournal(inventory)
        const evictedMigrated = await this._migrateEvictedSidecarToBee(
          new Map(inventory.map(row => [row.appKey, row]))
        )
        if (evictedMigrated) {
          inventory = await this._readBeeInventory()
          this._recoverRegistryJournal(inventory)
        }
        const migrated = await this._migrateJsonToBee(new Map(inventory.map(row => [row.appKey, row])))
        if (migrated) {
          inventory = await this._readBeeInventory()
          this._recoverRegistryJournal(inventory)
        }

        // Hydrate only after every row validated so a corrupt tail cannot leave
        // a partially adopted in-memory inventory.
        this.apps.clear()
        this.byAppId.clear()
        this._durableEntries.clear()
        this._entryGenerations.clear()
        const entries = []
        for (const { appKey, entry, tombstone } of inventory) {
          if (tombstone) continue
          this._hydrateEntry(appKey, entry)
          entries.push(this._reseedEntry(entry, appKey))
        }
        return entries.filter(e => e.appKey)
      } catch (err) {
        // A partial/failed Bee scan is not an empty inventory. The drive seal
        // must remain pending even during a concurrent shutdown race.
        throw registryInventoryError('bee-read-failed', err)
      }
    }

    // Legacy JSON path — pre-v0.8.25 behavior, used when no store
    // attached (tests, headless usage).
    await this._loadEvicted({ strict: this._physicalReadOnly })
    if (!this._filePath) return []

    let raw
    try {
      raw = await readFile(this._filePath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return []
      throw registryInventoryError('json-read-failed', err)
    }
    let data
    try { data = JSON.parse(raw) } catch (err) { throw registryInventoryError('json-corrupt', err) }
    const entries = validatedLegacyEntries(data)
    const activeEntries = entries.filter(entry =>
      !this.evicted.has(entry.appKey || entry.driveKey)
    )

    // Populate in-memory state only after the complete inventory validates.
    this.apps.clear()
    this.byAppId.clear()
    this._durableEntries.clear()
    this._entryGenerations.clear()
    for (const entry of activeEntries) {
      const appKey = entry.appKey || entry.driveKey
      this._hydrateEntry(appKey, entry)
    }

    return activeEntries.map(e => this._reseedEntry(e, e.appKey || e.driveKey))
  }

  async _loadLegacyJsonReadOnly () {
    await this._loadEvicted({ strict: true })
    if (!this._filePath) return []
    let raw
    try {
      raw = await readFile(this._filePath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return []
      throw registryInventoryError('json-read-failed', err)
    }
    let data
    try { data = JSON.parse(raw) } catch (err) { throw registryInventoryError('json-corrupt', err) }
    const entries = validatedLegacyEntries(data)
    const activeEntries = entries.filter(entry =>
      !this.evicted.has(entry.appKey || entry.driveKey)
    )
    this.apps.clear()
    this.byAppId.clear()
    this._durableEntries.clear()
    this._entryGenerations.clear()
    for (const entry of activeEntries) {
      const appKey = entry.appKey || entry.driveKey
      this._hydrateEntry(appKey, entry)
    }
    return activeEntries.map(entry => this._reseedEntry(entry, entry.appKey || entry.driveKey))
  }

  /**
   * v0.8.25 — Hydrate the in-memory Map with an entry loaded from
   * persistence (bee or JSON). Shared between both paths so the
   * normalization rules live in one place.
   */
  _hydrateEntry (appKey, entry) {
    const hasStorageProof = STORAGE_PROOF_FIELDS.every(field => entry[field] != null)
    const metadataBudget = validatePersistedMetadataBudget(entry)
    const hydrated = {
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
      anchored: hasStorageProof && entry.anchored === true,
      anchoredAt: hasStorageProof ? (entry.anchoredAt || null) : null,
      anchoredLength: hasStorageProof && typeof entry.anchoredLength === 'number' ? entry.anchoredLength : 0,
      lastAnchorCheck: entry.lastAnchorCheck || null,
      storageProvedDriveVersion: hasStorageProof && Number.isSafeInteger(entry.storageProvedDriveVersion) && entry.storageProvedDriveVersion > 0 ? entry.storageProvedDriveVersion : null,
      storageProvedMetaLength: Number.isSafeInteger(entry.storageProvedMetaLength) && entry.storageProvedMetaLength >= 0 ? entry.storageProvedMetaLength : null,
      storageProvedBlobLength: Number.isSafeInteger(entry.storageProvedBlobLength) && entry.storageProvedBlobLength >= 0 ? entry.storageProvedBlobLength : null,
      storageProvedTotalBytes: Number.isSafeInteger(entry.storageProvedTotalBytes) && entry.storageProvedTotalBytes >= 0 ? entry.storageProvedTotalBytes : null,
      storageProvedMetaFork: Number.isSafeInteger(entry.storageProvedMetaFork) && entry.storageProvedMetaFork >= 0 ? entry.storageProvedMetaFork : null,
      storageProvedBlobFork: Number.isSafeInteger(entry.storageProvedBlobFork) && entry.storageProvedBlobFork >= 0 ? entry.storageProvedBlobFork : null,
      storageMetadataBytesWritten: metadataBudget.bytes,
      storageMetadataRevision: metadataBudget.revision,
      maxStorage: Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
        ? Math.floor(entry.maxStorage)
        : null,
      leaseManaged: entry.leaseManaged === true,
      // drive and discoveryKey are set during reseeding
      drive: null,
      discoveryKey: null
    }
    this.apps.set(appKey, hydrated)
    this._durableEntries.set(appKey, { ...hydrated })
    this._entryGenerations.set(appKey, 0)
    this._metadataBudgets.set(appKey, metadataBudget)
    this._metadataTombstones.delete(appKey)
    this._metadataTombstoneEntries.delete(appKey)

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
      maxStorage: Number.isSafeInteger(e.maxStorage) && e.maxStorage > 0
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
    // Validate the in-memory tuple before normalization. Otherwise an invalid
    // field can be coerced to null below and silently turn a poisoned partial
    // proof into a legacy-looking row that fails only on the next restart.
    const hasStorageProof = validatePersistedStorageProof(entry)
    const shape = {
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
      anchored: hasStorageProof && entry.anchored === true,
      anchoredAt: hasStorageProof ? (entry.anchoredAt || null) : null,
      anchoredLength: hasStorageProof ? entry.anchoredLength : 0,
      lastAnchorCheck: entry.lastAnchorCheck || null,
      storageProvedDriveVersion: Number.isSafeInteger(entry.storageProvedDriveVersion) && entry.storageProvedDriveVersion > 0 ? entry.storageProvedDriveVersion : null,
      storageProvedMetaLength: Number.isSafeInteger(entry.storageProvedMetaLength) && entry.storageProvedMetaLength >= 0 ? entry.storageProvedMetaLength : null,
      storageProvedBlobLength: Number.isSafeInteger(entry.storageProvedBlobLength) && entry.storageProvedBlobLength >= 0 ? entry.storageProvedBlobLength : null,
      storageProvedTotalBytes: Number.isSafeInteger(entry.storageProvedTotalBytes) && entry.storageProvedTotalBytes >= 0 ? entry.storageProvedTotalBytes : null,
      storageProvedMetaFork: Number.isSafeInteger(entry.storageProvedMetaFork) && entry.storageProvedMetaFork >= 0 ? entry.storageProvedMetaFork : null,
      storageProvedBlobFork: Number.isSafeInteger(entry.storageProvedBlobFork) && entry.storageProvedBlobFork >= 0 ? entry.storageProvedBlobFork : null,
      storageMetadataBytesWritten: Number.isSafeInteger(entry.storageMetadataBytesWritten) && entry.storageMetadataBytesWritten >= 0
        ? entry.storageMetadataBytesWritten
        : 0,
      storageMetadataRevision: Number.isSafeInteger(entry.storageMetadataRevision) && entry.storageMetadataRevision >= 0
        ? entry.storageMetadataRevision
        : 0,
      maxStorage: Number.isSafeInteger(entry.maxStorage) && entry.maxStorage > 0
        ? Math.floor(entry.maxStorage)
        : null,
      leaseManaged: entry.leaseManaged === true
    }
    validatePersistedStorageProof(shape)
    const preflightLimit = this._persistenceMode === 'bee'
      ? APP_REGISTRY_ACTIVE_METADATA_BUDGET_BYTES
      : STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES
    if (b4a.byteLength(JSON.stringify(shape)) + APP_REGISTRY_LEGACY_ROW_PREFLIGHT_MARGIN_BYTES >
        preflightLimit) {
      const err = new Error('APP_REGISTRY_ENTRY_EXCEEDS_METADATA_COMMITMENT')
      err.code = 'APP_REGISTRY_ENTRY_EXCEEDS_METADATA_COMMITMENT'
      throw err
    }
    return shape
  }

  _failRegistryJournal (reason, cause = null) {
    if (this.storageAdmission && typeof this.storageAdmission.failClosed === 'function') {
      this.storageAdmission.failClosed(reason)
    }
    const err = new Error('APP_REGISTRY_JOURNAL_FAILED: ' + reason)
    err.code = 'APP_REGISTRY_JOURNAL_FAILED'
    err.reason = reason
    if (cause) err.cause = cause
    return err
  }

  _runRegistryJournalMutation (run) {
    if (this.storageAdmission && typeof this.storageAdmission.runKeyMutation === 'function') {
      return this.storageAdmission.runKeyMutation(APP_REGISTRY_JOURNAL_AUTHORITY_KEY, run)
    }
    return Promise.resolve().then(run)
  }

  _assertRegistryJournalCurrent () {
    const journal = this._registryJournal
    const core = this._bee?.core || this._bee?.feed
    const byteLength = safeCoreMetric(core, 'byteLength')
    const length = safeCoreMetric(core, 'length')
    const fork = safeCoreMetric(core, 'fork')
    if (!journal || byteLength === null || length === null || fork === null) {
      throw this._failRegistryJournal('app-registry-journal-measurement-unavailable')
    }
    if (journal.reservedBytes !== 0 || byteLength !== journal.expectedByteLength ||
        length !== journal.expectedLength || fork !== journal.expectedFork) {
      throw this._failRegistryJournal('app-registry-journal-drift')
    }
    let chargedBytes = 0
    for (const budget of this._metadataBudgets.values()) {
      if (!Number.isSafeInteger(chargedBytes + budget.bytes)) {
        throw this._failRegistryJournal('app-registry-journal-budget-overflow')
      }
      chargedBytes += budget.bytes
    }
    if (chargedBytes !== journal.chargedBytes ||
        journal.baselineBytes + chargedBytes !== byteLength) {
      throw this._failRegistryJournal('app-registry-journal-ledger-drift')
    }
    return { journal, core, byteLength, length, fork }
  }

  _reserveRegistryJournalCapacity (newKeyCount, currentBytes, opts = {}) {
    const journal = this._registryJournal
    const distinctKeys = journal.distinctKeys + newKeyCount
    const boundBytes = journal.baselineBytes +
      distinctKeys * STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES
    if (!Number.isSafeInteger(boundBytes) || boundBytes < currentBytes || boundBytes <= 0) {
      throw this._failRegistryJournal('app-registry-journal-capacity-invalid')
    }
    if (!this.storageAdmission) return { boundBytes, distinctKeys, token: null }

    if (opts.recovery === true) {
      const record = this.storageAdmission.adoptRecovery(
        APP_REGISTRY_JOURNAL_AUTHORITY_KEY,
        boundBytes,
        { kind: 'workload', metadataOverheadBytes: 0, actualBytes: currentBytes }
      )
      if (!record) throw this._failRegistryJournal('app-registry-journal-recovery-reservation-failed')
      return { boundBytes, distinctKeys, token: null }
    }

    const existing = this.storageAdmission.get(APP_REGISTRY_JOURNAL_AUTHORITY_KEY)
    if (existing?.state === 'committed' && existing.boundBytes >= boundBytes) {
      return { boundBytes: existing.boundBytes, distinctKeys, token: null }
    }
    const token = this.storageAdmission.reserve(
      APP_REGISTRY_JOURNAL_AUTHORITY_KEY,
      boundBytes,
      {
        kind: 'workload',
        metadataOverheadBytes: 0,
        authoritativeSizeBytes: currentBytes,
        measuredActualBytes: currentBytes
      }
    )
    if (!token?.allowed) {
      const err = new Error('APP_REGISTRY_STORAGE_ADMISSION_BLOCKED')
      err.code = 'APP_REGISTRY_STORAGE_ADMISSION_BLOCKED'
      err.admission = token
      throw err
    }
    return { boundBytes, distinctKeys, token }
  }

  async _appendMeasuredBeeShapes (items, opts = {}) {
    const phase = opts.recovery === true ? 'recovery' : 'runtime'
    return this._runPhysicalWrite(
      `app-registry-bee-append:${phase}`,
      phase,
      () => this._appendMeasuredBeeShapesUnderCeiling(items, opts)
    )
  }

  async _appendMeasuredBeeShapesUnderCeiling (items, opts = {}) {
    if (!Array.isArray(items) || items.length === 0) return []
    const { journal, core, byteLength: beforeBytes, length: beforeLength, fork: beforeFork } =
      this._assertRegistryJournalCurrent()
    const seen = new Set()
    let newKeyCount = 0
    for (const item of items) {
      if (!item || !CANONICAL_APP_KEY.test(item.appKey) || seen.has(item.appKey)) {
        throw this._failRegistryJournal('app-registry-journal-plan-invalid')
      }
      seen.add(item.appKey)
      const current = this._metadataBudgets.get(item.appKey)
      const prior = item.priorBudget || current || { bytes: 0, revision: 0 }
      if (!Number.isSafeInteger(prior.bytes) || prior.bytes < 0 ||
          !Number.isSafeInteger(prior.revision) || prior.revision < 0 ||
          (current && (current.bytes !== prior.bytes || current.revision !== prior.revision))) {
        throw this._failRegistryJournal('app-registry-journal-prior-budget-invalid')
      }
      item.priorBudget = prior
      if (!current) newKeyCount++
    }

    let candidates = items.map(item => item.priorBudget.bytes)
    let batch = null
    let blocks = null
    let shapes = null
    try {
      for (let attempt = 0; attempt < APP_REGISTRY_PLAN_MAX_ATTEMPTS; attempt++) {
        if (batch && typeof batch.close === 'function') await batch.close()
        batch = this._bee.batch()
        shapes = []
        for (let i = 0; i < items.length; i++) {
          const item = items[i]
          if (!Number.isSafeInteger(item.priorBudget.revision + 1)) {
            throw this._failRegistryJournal('app-registry-journal-revision-overflow')
          }
          const shape = {
            ...item.shape,
            appKey: item.appKey,
            ...(item.tombstone ? { storageDeleted: true } : { storageDeleted: undefined }),
            storageMetadataBytesWritten: candidates[i],
            storageMetadataRevision: item.priorBudget.revision + 1
          }
          if (!item.tombstone) delete shape.storageDeleted
          shapes.push(shape)
          await batch.put(item.appKey, shape)
        }
        if (typeof batch.toBlocks !== 'function') {
          throw this._failRegistryJournal('app-registry-journal-planning-unavailable')
        }
        blocks = batch.toBlocks()
        if (!Array.isArray(blocks) || blocks.length !== items.length) {
          throw this._failRegistryJournal('app-registry-journal-plan-cardinality-invalid')
        }
        const next = blocks.map((block, i) => {
          const blockBytes = b4a.isBuffer(block) ? block.byteLength : null
          if (!Number.isSafeInteger(blockBytes) || blockBytes <= 0 ||
              !Number.isSafeInteger(items[i].priorBudget.bytes + blockBytes)) {
            throw this._failRegistryJournal('app-registry-journal-plan-bytes-invalid')
          }
          return items[i].priorBudget.bytes + blockBytes
        })
        if (next.every((value, i) => value === candidates[i])) break
        candidates = next
        if (attempt === APP_REGISTRY_PLAN_MAX_ATTEMPTS - 1) {
          throw this._failRegistryJournal('app-registry-journal-plan-did-not-converge')
        }
      }

      for (let i = 0; i < items.length; i++) {
        const maxBytes = items[i].tombstone
          ? STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES
          : APP_REGISTRY_ACTIVE_METADATA_BUDGET_BYTES
        if (candidates[i] > maxBytes) {
          const err = new Error('APP_REGISTRY_METADATA_BUDGET_EXCEEDED')
          err.code = 'APP_REGISTRY_METADATA_BUDGET_EXCEEDED'
          err.appKey = items[i].appKey
          err.usedBytes = items[i].priorBudget.bytes
          err.attemptedBytes = candidates[i] - items[i].priorBudget.bytes
          err.maxBytes = maxBytes
          throw err
        }
        shapes[i].storageMetadataBytesWritten = candidates[i]
        validatePersistedMetadataBudget(shapes[i])
      }

      const plannedBytes = sumBlockBytes(blocks)
      if (plannedBytes === null || plannedBytes <= 0 ||
          safeCoreMetric(core, 'byteLength') !== beforeBytes ||
          safeCoreMetric(core, 'length') !== beforeLength ||
          safeCoreMetric(core, 'fork') !== beforeFork) {
        throw this._failRegistryJournal('app-registry-journal-plan-mutated-feed')
      }
      const reservation = this._reserveRegistryJournalCapacity(newKeyCount, beforeBytes, opts)
      journal.reservedBytes = plannedBytes

      let flushError = null
      try {
        await batch.flush()
      } catch (err) {
        flushError = err
      }

      const afterBytes = safeCoreMetric(core, 'byteLength')
      const afterLength = safeCoreMetric(core, 'length')
      const afterFork = safeCoreMetric(core, 'fork')
      journal.reservedBytes = 0
      const settled = afterBytes === beforeBytes + plannedBytes &&
        afterLength === beforeLength + blocks.length && afterFork === beforeFork
      if (flushError || !settled) {
        const unchanged = afterBytes === beforeBytes && afterLength === beforeLength && afterFork === beforeFork
        if (unchanged && reservation.token) this.storageAdmission.rollback(reservation.token)
        if (!unchanged) {
          journal.expectedByteLength = afterBytes
          journal.expectedLength = afterLength
          journal.expectedFork = afterFork
        }
        throw this._failRegistryJournal(
          unchanged ? 'app-registry-journal-append-rejected' : 'app-registry-journal-settlement-ambiguous',
          flushError
        )
      }

      journal.chargedBytes += plannedBytes
      journal.distinctKeys = reservation.distinctKeys
      journal.expectedByteLength = afterBytes
      journal.expectedLength = afterLength
      journal.expectedFork = afterFork
      for (let i = 0; i < items.length; i++) {
        const budget = { bytes: candidates[i], revision: shapes[i].storageMetadataRevision }
        this._metadataBudgets.set(items[i].appKey, budget)
        if (items[i].tombstone) {
          this._metadataTombstones.add(items[i].appKey)
          this._metadataTombstoneEntries.set(items[i].appKey, shapes[i])
          if (Number.isSafeInteger(shapes[i].evictedAt) && shapes[i].evictedAt > 0) {
            this.evicted.set(items[i].appKey, shapes[i].evictedAt)
          } else {
            this.evicted.delete(items[i].appKey)
          }
        } else {
          this._metadataTombstones.delete(items[i].appKey)
          this._metadataTombstoneEntries.delete(items[i].appKey)
          this.evicted.delete(items[i].appKey)
        }
      }

      if (this.storageAdmission) {
        const authoritySettled = reservation.token
          ? this.storageAdmission.commit(reservation.token, {
            boundBytes: reservation.boundBytes,
            actualBytes: afterBytes
          })
          : this.storageAdmission.reconcileActual(APP_REGISTRY_JOURNAL_AUTHORITY_KEY, afterBytes)
        if (!authoritySettled) {
          throw this._failRegistryJournal('app-registry-journal-authority-settlement-failed')
        }
      }
      return shapes
    } catch (err) {
      journal.reservedBytes = 0
      if (batch && safeCoreMetric(core, 'byteLength') === beforeBytes &&
          typeof batch.close === 'function') {
        try { await batch.close() } catch (_) {}
      }
      throw err
    }
  }

  /**
   * Save registry to disk. Uses atomic write (write temp, rename).
   * Coalesces rapid writes — only one save happens at a time.
   */
  async save (opts = {}) {
    const throwOnError = opts.throwOnError === true
    this._assertPhysicalWritesAvailable()

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
        this._emitSafely('error', { context: 'save-bee', error: err })
        if (throwOnError) throw err
        return
      }
    }

    if (this._persistenceMode === 'bee' && throwOnError) {
      throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
    }

    // Legacy JSON mode — keep pre-v0.8.25 whole-file rewrite behavior.
    if (!this._filePath) {
      if (throwOnError) throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
      return
    }

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
          await this._runPhysicalWrite('app-registry-json-save', 'runtime', async () => {
            await writeFile(tmpPath, JSON.stringify(entries, null, 2))
            await rename(tmpPath, this._filePath)
          })
          lastError = null
        } catch (err) {
          lastError = err
          this._emitSafely('error', { context: 'save', error: err })
        }
      } while (this._savePending)
    } finally {
      this._saving = false
      const waiters = this._saveIdleWaiters.splice(0)
      for (const resolve of waiters) resolve(lastError)
    }

    if (lastError && (throwOnError || lastError.code === 'APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE')) {
      throw lastError
    }
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
    const previous = this._beeWriteTail
    const op = this._runRegistryJournalMutation(() => previous.then(run, run))
    this._beeWriteTail = op.catch(() => {})
    this._pendingBeeOps.add(op)
    op.then(
      () => this._pendingBeeOps.delete(op),
      () => this._pendingBeeOps.delete(op)
    )
    return op
  }

  async _persistEntryToBee (appKey, opts = {}) {
    const strict = opts.strict === true
    this._assertPhysicalWritesAvailable()
    if (!this._beeReady || !this._bee) {
      if (strict) throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
      return
    }
    const entry = this.apps.get(appKey)
    if (!entry) {
      if (strict) throw new Error('APP_REGISTRY_ENTRY_MISSING')
      return
    }
    const generation = this._entryGenerations.get(appKey) || 0
    const entrySnapshot = { ...entry }
    const authority = this._bee
    return this._enqueueBeeWrite(async () => {
      if (!this._beeReady || this._bee !== authority) {
        if (strict) throw new Error('APP_REGISTRY_PERSISTENCE_AUTHORITY_CHANGED')
        return
      }
      const priorWasTombstone = this._metadataTombstones.has(appKey)
      try {
        const priorBudget = this._metadataBudgets.get(appKey) ||
          validatePersistedMetadataBudget(entrySnapshot)
        const shape = this._persistShape(appKey, {
          ...entrySnapshot,
          storageMetadataBytesWritten: priorBudget.bytes,
          storageMetadataRevision: priorBudget.revision
        })
        await this._appendMeasuredBeeShapes([{
          appKey,
          shape,
          priorBudget,
          tombstone: false
        }])
        const budget = this._metadataBudgets.get(appKey)
        const live = this.apps.get(appKey)
        if (live && budget) {
          live.storageMetadataBytesWritten = budget.bytes
          live.storageMetadataRevision = budget.revision
        }
        if (budget) {
          this._durableEntries.set(appKey, {
            ...entrySnapshot,
            storageMetadataBytesWritten: budget.bytes,
            storageMetadataRevision: budget.revision
          })
        }
      } catch (cause) {
        const err = priorWasTombstone && cause?.code === 'APP_REGISTRY_METADATA_BUDGET_EXCEEDED'
          ? Object.assign(new Error('APP_REGISTRY_KEY_RETIRED_METADATA_EXHAUSTED'), {
            code: 'APP_REGISTRY_KEY_RETIRED_METADATA_EXHAUSTED',
            appKey,
            cause
          })
          : cause
        this._restoreDurableEntry(appKey, generation)
        this._emitSafely('error', { context: 'persist-bee', appKey, error: err })
        throw err
      }
    })
  }

  async _deleteEntryFromBee (appKey, opts = {}) {
    const strict = opts.strict === true
    this._assertPhysicalWritesAvailable()
    if (!this._beeReady || !this._bee) {
      if (strict) throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
      return
    }
    const generation = this._entryGenerations.get(appKey) || 0
    const authority = this._bee
    return this._enqueueBeeWrite(async () => {
      if (!this._beeReady || this._bee !== authority) {
        if (strict) throw new Error('APP_REGISTRY_PERSISTENCE_AUTHORITY_CHANGED')
        return
      }
      try {
        const priorBudget = this._metadataBudgets.get(appKey) || { bytes: 0, revision: 0 }
        const evictedAt = Number.isSafeInteger(opts.evictedAt) && opts.evictedAt > 0
          ? opts.evictedAt
          : null
        await this._appendMeasuredBeeShapes([{
          appKey,
          shape: { appKey, evictedAt },
          priorBudget,
          tombstone: true
        }])
        this._durableEntries.delete(appKey)
      } catch (err) {
        this._restoreDurableEntry(appKey, generation)
        this._emitSafely('error', { context: 'delete-bee', appKey, error: err })
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
    appKey = canonicalRuntimeAppKey(appKey)
    const throwOnError = opts.throwOnError === true
    try {
      if (appKey === null) throw new Error('Invalid app key: must be 64 hex characters')
      if (this._persistenceMode === 'bee') {
        await this._persistEntryToBee(appKey, { strict: true })
        return
      }
      if (!this._filePath) throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
      this._clearSaveDebounce()
      await this.save({ throwOnError: true })
    } catch (err) {
      if (throwOnError || err?.code === 'APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE') throw err
    }
  }

  async persistDelete (appKey, opts = {}) {
    appKey = canonicalRuntimeAppKey(appKey)
    const throwOnError = opts.throwOnError === true
    try {
      if (appKey === null) throw new Error('Invalid app key: must be 64 hex characters')
      if (this._persistenceMode === 'bee') {
        await this._deleteEntryFromBee(appKey, {
          strict: true,
          evictedAt: opts.evictedAt
        })
        return
      }
      if (!this._filePath) throw new Error('APP_REGISTRY_PERSISTENCE_UNAVAILABLE')
      this._clearSaveDebounce()
      await this.save({ throwOnError: true })
    } catch (err) {
      if (throwOnError || err?.code === 'APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE') throw err
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
    this._assertPhysicalWritesAvailable()
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
    // A physically unenforced registry is intentionally read-only. If it has
    // admitted no Bee mutation, there is no durable writer to flush during an
    // interrupted startup; treating the unopened journal as a flush failure
    // would strand Corestore despite zero registry debt.
    if (this._physicalReadOnly && (!this._pendingBeeOps || this._pendingBeeOps.size === 0)) return
    const unopenedBeeWithoutDebt = this._persistenceMode === 'bee' &&
      this._beeReady === false &&
      (!this._pendingBeeOps || this._pendingBeeOps.size === 0) &&
      this._registryJournal === null &&
      this._durableEntries.size === 0 &&
      this.apps.size === 0 &&
      this._metadataTombstones.size === 0
    if (unopenedBeeWithoutDebt) return
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
