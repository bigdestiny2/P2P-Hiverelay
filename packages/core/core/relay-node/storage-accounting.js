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

const DEFAULT_TICK_MS = 5_000
const DEFAULT_BATCH = 25

async function coreStorageBytes (core) {
  if (!core || typeof core.info !== 'function') return 0
  try {
    const info = await core.info({ storage: true })
    const s = info && info.storage
    if (!s) return 0
    return (s.oplog || 0) + (s.tree || 0) + (s.blocks || 0) + (s.bitfield || 0)
  } catch {
    return 0 // closed/closing core mid-measure — skip this pass
  }
}

export class StorageAccounting extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.appRegistry) throw new Error('StorageAccounting: appRegistry is required')
    this.appRegistry = opts.appRegistry
    this.tickMs = Number.isFinite(opts.tickMs) ? Math.max(500, opts.tickMs) : DEFAULT_TICK_MS
    this.batchSize = Number.isFinite(opts.batchSize) ? Math.max(1, opts.batchSize) : DEFAULT_BATCH

    this._bytes = new Map() // appKeyHex -> { bytes, measuredAt }
    this._cursor = 0
    this._interval = null
    this._sweeping = false
    this._fullSweeps = 0
    this._lastFullSweepAt = null
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
    const meta = await coreStorageBytes(drive.core)
    const blobs = drive.blobs ? await coreStorageBytes(drive.blobs.core) : 0
    const rec = { bytes: meta + blobs, measuredAt: Date.now() }
    this._bytes.set(appKeyHex, rec)
    return rec.bytes
  }

  async _tick () {
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
    let total = 0
    for (const rec of this._bytes.values()) total += rec.bytes
    return {
      totalBytes: total,
      measuredEntries: this._bytes.size,
      fullSweeps: this._fullSweeps,
      lastFullSweepAt: this._lastFullSweepAt
    }
  }
}
