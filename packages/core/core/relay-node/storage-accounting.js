// storage-accounting.js — honest per-drive on-disk byte measurement.
//
// "Stored: 0 B" while the corestore holds 13 GB is how the fleet's disks
// filled unnoticed (2026-06-11: utah + sing-1 hit 100% during a roll).
// Worse, the replication-repair storage guard computes
// `maxStorageBytes - seeder.totalBytesStored`, and totalBytesStored only
// counts bytes routed through Seeder.seedCore — approximately nothing on
// a relay whose content arrives via appRegistry drives. The guard never
// bound, so adoption was effectively uncapped.
//
// This module measures reality: for every appRegistry entry it sums the
// actual file bytes of the drive's two hypercores (meta + blobs) via
// `core.info({ storage: true })`, which stat()s oplog/tree/blocks/
// bitfield on disk. Results are cached per appKey.
//
// Pacing: measuring ~1,200 drives stat()s ~10k files — fine once, rude
// continuously. The sweep walks a fixed batch per tick (default 25 every
// 5s ≈ full pass over 1,200 drives in ~4 min) and then starts over, so
// totals converge quickly after boot and stay fresh without IO spikes.

import { EventEmitter } from 'events'
import { readdir, stat } from 'fs/promises'
import { join } from 'path'

const DEFAULT_TICK_MS = 5_000
const DEFAULT_BATCH = 25
const DEFAULT_INFO_TIMEOUT_MS = 8_000
const DEFAULT_DISK_INTERVAL_MS = 60_000

/**
 * Ground-truth on-disk footprint: recursively sum the file bytes under `dir`.
 * This is what `du` sees and what actually fills the disk — unlike the
 * per-entry drive walk it CANNOT be fooled by bare seeded cores or lazily-
 * unloaded Hyperdrives with no live `entry.drive` (the reason accounting read
 * ~0 on registry-driven relays while the disk held 19 GB, so the adoption
 * guard never bound). Robust: unreadable dirs/files are skipped; symlinks are
 * not followed (only regular files count).
 */
export async function dirBytes (dir) {
  if (!dir) return 0
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return 0
  }
  let total = 0
  for (const e of entries) {
    const p = join(dir, e.name)
    try {
      if (e.isDirectory()) total += await dirBytes(p)
      else if (e.isFile()) total += (await stat(p)).size
    } catch {
      // racing deletes (eviction/purge), perms, broken links — skip
    }
  }
  return total
}

/**
 * Race a promise against a timeout, resolving the fallback instead of
 * rejecting. Cores damaged by a disk-full crash can wedge their await
 * forever (info()/ready() on a truncated oplog) — without this, one bad
 * core froze the whole accounting sweep AND the eviction pass behind a
 * never-clearing in-progress latch (utah + sing-1, 2026-06-11).
 */
export function raceTimeout (promise, ms, fallback) {
  let timer
  return Promise.race([
    promise.then(
      (v) => v,
      () => fallback // errors collapse to the fallback too
    ),
    new Promise((resolve) => {
      // Deliberately NOT unref'd: an unref'd race against a wedged
      // promise leaves the event loop with nothing referenced, so the
      // process (or a test runner) sees a deadlock before the timer can
      // fire. These timers are short-lived and cleared on resolution.
      timer = setTimeout(() => resolve(fallback), ms)
    })
  ]).finally(() => clearTimeout(timer))
}

async function coreStorageBytes (core, timeoutMs = DEFAULT_INFO_TIMEOUT_MS) {
  if (!core || typeof core.info !== 'function') return 0
  const info = await raceTimeout(core.info({ storage: true }), timeoutMs, null)
  const s = info && info.storage
  if (!s) return 0
  return (s.oplog || 0) + (s.tree || 0) + (s.blocks || 0) + (s.bitfield || 0)
}

export class StorageAccounting extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.appRegistry) throw new Error('StorageAccounting: appRegistry is required')
    this.appRegistry = opts.appRegistry
    // Real on-disk corestore path (config.storage). When set, getSummary()
    // reports the measured disk footprint as the authoritative total — the
    // per-entry drive walk alone undercounts whenever entries are bare cores
    // or unhydrated drives, which is most of them on a busy relay.
    this.storagePath = opts.storagePath || null
    this.tickMs = Number.isFinite(opts.tickMs) ? Math.max(500, opts.tickMs) : DEFAULT_TICK_MS
    this.batchSize = Number.isFinite(opts.batchSize) ? Math.max(1, opts.batchSize) : DEFAULT_BATCH
    this.infoTimeoutMs = Number.isFinite(opts.infoTimeoutMs) ? Math.max(50, opts.infoTimeoutMs) : DEFAULT_INFO_TIMEOUT_MS
    this.diskIntervalMs = Number.isFinite(opts.diskIntervalMs) ? Math.max(1000, opts.diskIntervalMs) : DEFAULT_DISK_INTERVAL_MS

    this._bytes = new Map() // appKeyHex -> { bytes, measuredAt }
    this._cursor = 0
    this._interval = null
    this._sweeping = false
    this._fullSweeps = 0
    this._lastFullSweepAt = null
    this._diskBytes = null // measured du(storagePath); null until first measure
    this._diskMeasuring = false
    this._lastDiskMeasureAt = 0
  }

  start () {
    if (this._interval) return
    this._interval = setInterval(() => {
      this._tick().catch(err => this.emit('error', err))
    }, this.tickMs)
    if (this._interval.unref) this._interval.unref()
    // First batch immediately so boots converge fast.
    this._tick().catch(err => this.emit('error', err))
  }

  stop () {
    if (this._interval) {
      clearInterval(this._interval)
      this._interval = null
    }
  }

  /** Measure one entry's drive right now (used by eviction pre-checks). */
  async measure (appKeyHex) {
    const entry = this.appRegistry.get(appKeyHex)
    const drive = entry && entry.drive
    if (!drive) return null
    const meta = await coreStorageBytes(drive.core, this.infoTimeoutMs)
    const blobs = drive.blobs ? await coreStorageBytes(drive.blobs.core, this.infoTimeoutMs) : 0
    const rec = { bytes: meta + blobs, measuredAt: Date.now() }
    this._bytes.set(appKeyHex, rec)
    return rec.bytes
  }

  /**
   * Measure the real on-disk corestore footprint (du of storagePath). Cheap
   * enough at the default once-a-minute cadence; latched so a slow walk never
   * piles up. This is the number the adoption guard must trust.
   */
  async measureDisk () {
    if (this._diskMeasuring || !this.storagePath) return this._diskBytes
    this._diskMeasuring = true
    try {
      this._diskBytes = await dirBytes(this.storagePath)
      this._lastDiskMeasureAt = Date.now()
      return this._diskBytes
    } finally {
      this._diskMeasuring = false
    }
  }

  async _tick () {
    // Real-disk measurement runs on its own (throttled) cadence, independent
    // of the per-entry sweep — so the total is correct even when the registry
    // is empty but bare cores still occupy the disk. Fire-and-forget; never
    // blocks the per-entry batch behind a du walk.
    if (this.storagePath && !this._diskMeasuring &&
        (Date.now() - this._lastDiskMeasureAt) >= this.diskIntervalMs) {
      this.measureDisk().catch(err => this.emit('error', err))
    }
    if (this._sweeping) return // a slow batch must not pile up behind itself
    this._sweeping = true
    try {
      const keys = this.appRegistry.keys
        ? [...this.appRegistry.keys()]
        : [...(this.appRegistry.entries ? this.appRegistry.entries() : [])].map(e => Array.isArray(e) ? e[0] : e)
      if (!keys.length) return

      if (this._cursor >= keys.length) {
        this._cursor = 0
        this._fullSweeps++
        this._lastFullSweepAt = Date.now()
        // Drop cache rows for entries that no longer exist (unseeded/evicted).
        const live = new Set(keys)
        for (const k of this._bytes.keys()) {
          if (!live.has(k)) this._bytes.delete(k)
        }
      }

      const batch = keys.slice(this._cursor, this._cursor + this.batchSize)
      this._cursor += batch.length
      for (const key of batch) {
        await this.measure(key)
      }
    } finally {
      this._sweeping = false
    }
  }

  getBytes (appKeyHex) {
    const rec = this._bytes.get(appKeyHex)
    return rec ? rec.bytes : null
  }

  /** Largest measured entries first — eviction's ranking input. */
  getTop (n = 20) {
    return [...this._bytes.entries()]
      .map(([appKey, rec]) => ({ appKey, bytes: rec.bytes, measuredAt: rec.measuredAt }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, n)
  }

  getSummary () {
    let perEntry = 0
    for (const rec of this._bytes.values()) perEntry += rec.bytes
    // Authoritative total = the measured on-disk footprint when available
    // (catches bare/lazy cores the per-entry walk misses); the per-entry sum
    // is only ever a subset, so max() is a safe floor before the first du.
    const totalBytes = this._diskBytes != null ? Math.max(this._diskBytes, perEntry) : perEntry
    return {
      totalBytes,
      diskBytes: this._diskBytes,
      perEntryBytes: perEntry,
      measuredEntries: this._bytes.size,
      fullSweeps: this._fullSweeps,
      lastFullSweepAt: this._lastFullSweepAt
    }
  }
}
