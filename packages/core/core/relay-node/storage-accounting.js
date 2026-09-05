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
import { sharedCoreInfo } from '../shared-flight-registry.js'
import { CompletionScheduler, strictPositiveInteger } from '../completion-scheduler.js'
import {
  StorageAccountingEpoch,
  runStorageAccountingEpoch
} from './storage-accounting-epoch.js'

const DEFAULT_TICK_MS = 5_000
const DEFAULT_BATCH = 25
const DEFAULT_INFO_TIMEOUT_MS = 8_000
const DISK_SUCCESS_INTERVAL_MS = 30 * 60 * 1000
const DISK_SUCCESS_JITTER_MS = 3 * 60 * 1000
const DISK_RETRY_MIN_MS = 60 * 1000
const DISK_RETRY_MAX_MS = 30 * 60 * 1000
const DISK_WAITER_DEFAULT_MS = 5_000
const DISK_WAITER_MAX_MS = 30_000
const DISK_MAX_WAITERS = 32
const MAX_ENTRY_BATCH = 64
const MAX_TOP_ENTRIES = 100

class AccountingBytesMap extends Map {
  constructor () {
    super()
    this.totalBytes = 0
  }

  set (key, value) {
    const previous = super.get(key)
    if (previous && Number.isFinite(previous.bytes)) this.totalBytes -= previous.bytes
    super.set(key, value)
    if (value && Number.isFinite(value.bytes)) this.totalBytes += value.bytes
    return this
  }

  delete (key) {
    const previous = super.get(key)
    const deleted = super.delete(key)
    if (deleted && previous && Number.isFinite(previous.bytes)) this.totalBytes -= previous.bytes
    return deleted
  }

  clear () {
    super.clear()
    this.totalBytes = 0
  }
}

function retainTopEntry (rows, row) {
  const existing = rows.findIndex(item => item.appKey === row.appKey)
  if (existing !== -1) rows.splice(existing, 1)
  rows.push(row)
  rows.sort((a, b) => (b.bytes - a.bytes) || a.appKey.localeCompare(b.appKey))
  if (rows.length > MAX_TOP_ENTRIES) rows.length = MAX_TOP_ENTRIES
}

function positiveDeadline (value, fallback, maximum, label) {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`)
  }
  return Math.min(value, maximum)
}

function accountingError (code, message, details = null) {
  const err = new Error(message)
  err.code = code
  err.details = details
  return err
}

function diskJitter (random) {
  const unit = Math.max(0, Math.min(1, Number(random()) || 0))
  return Math.min(DISK_SUCCESS_JITTER_MS, Math.floor(unit * (DISK_SUCCESS_JITTER_MS + 1)))
}

export async function dirBytes (dir) {
  if (!dir) return 0
  const result = await runStorageAccountingEpoch(dir)
  return result.complete ? result.bytes : 0
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
  const info = await sharedCoreInfo(core, { timeoutMs }).catch(() => null)
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
    this.tickMs = opts.tickMs === undefined
      ? DEFAULT_TICK_MS
      : strictPositiveInteger(opts.tickMs, 'StorageAccounting tickMs')
    this.batchSize = opts.batchSize === undefined
      ? DEFAULT_BATCH
      : strictPositiveInteger(opts.batchSize, 'StorageAccounting batchSize', MAX_ENTRY_BATCH)
    this.infoTimeoutMs = Number.isFinite(opts.infoTimeoutMs) ? Math.max(50, opts.infoTimeoutMs) : DEFAULT_INFO_TIMEOUT_MS
    this._now = typeof opts.now === 'function' ? opts.now : Date.now
    this._random = typeof opts.random === 'function' ? opts.random : Math.random
    this._setTimeout = typeof opts.setTimeout === 'function' ? opts.setTimeout : setTimeout
    this._clearTimeout = typeof opts.clearTimeout === 'function' ? opts.clearTimeout : clearTimeout
    this._epochFactory = typeof opts.epochFactory === 'function'
      ? opts.epochFactory
      : (storagePath) => new StorageAccountingEpoch(storagePath, { limits: opts.epochLimits })

    this._bytes = new AccountingBytesMap() // appKeyHex -> { bytes, measuredAt }
    // External byte sources outside the appRegistry drive walk — e.g. the
    // blind shard-store, whose bytes live in a dedicated hypercore, NOT an
    // appRegistry Hyperdrive, so the per-entry sweep never sees them. Each
    // source is a () => number (bytes). Counted into getSummary().sourceBytes
    // and folded into totalBytes so shard bytes are no longer invisible to the
    // adoption/eviction guards (STO-005).
    this._sources = new Map() // name -> () => number
    this._topWorking = []
    this._topPublished = []
    this._entryScheduler = null
    this._sweeping = false
    this._fullSweeps = 0
    this._lastFullSweepAt = null
    this._diskBytes = null // measured du(storagePath); null until first measure
    this._diskMeasurementComplete = false
    this._lastCompleteDiskSample = null
    this._lastDiskAttempt = null
    this._diskEpoch = null
    this._diskEpochPromise = null
    this._diskTimer = null
    this._diskNextDueAt = 0
    this._diskRetryMs = DISK_RETRY_MIN_MS
    this._diskFailedDrain = null
    this._diskWaiters = new Set()
    this._started = false
    this._stopping = false
    this._stopPromise = null
    this._registryListenerAttached = false
    this._onRegistryChange = ({ type, appKey } = {}) => {
      if (type !== 'delete' || typeof appKey !== 'string') return
      this._bytes.delete(appKey)
      this._topWorking = this._topWorking.filter(row => row.appKey !== appKey)
      this._topPublished = this._topPublished.filter(row => row.appKey !== appKey)
    }
    this._diskStats = {
      epochsStarted: 0,
      epochsCompleted: 0,
      epochsFailed: 0,
      coalesced: 0,
      waiterTimeouts: 0,
      waiterOverflow: 0
    }
  }

  start () {
    if (this._started) return
    if (this._stopping) throw accountingError('STORAGE_ACCOUNTING_STOPPED', 'StorageAccounting cannot restart after stop')
    if (typeof this.appRegistry.page !== 'function') {
      throw new TypeError('StorageAccounting: appRegistry.page is required for bounded accounting')
    }
    this._started = true
    this._attachRegistryListener()
    this._entryScheduler = new CompletionScheduler({
      name: 'storage-accounting-drives',
      intervalMs: this.tickMs,
      run: async () => {
        try {
          return await this._tick()
        } catch (err) {
          this.emit('error', err)
          throw err
        }
      }
    })
    // First bounded page immediately so boots converge quickly. Incomplete
    // high-water cycles coalesce into the scheduler's next completion turn.
    this._entryScheduler.start()
    if (this.storagePath) this._scheduleDiskEpoch(0)
  }

  _attachRegistryListener () {
    if (!this._registryListenerAttached && typeof this.appRegistry.on === 'function') {
      this.appRegistry.on('change', this._onRegistryChange)
      this._registryListenerAttached = true
    }
  }

  stop () {
    if (this._stopPromise) return this._stopPromise
    this._stopPromise = this._stop()
    return this._stopPromise
  }

  async _stop () {
    this._stopping = true
    this._started = false
    if (this._entryScheduler) await this._entryScheduler.stop()
    this._entryScheduler = null
    if (this._diskTimer) this._clearTimeout(this._diskTimer)
    this._diskTimer = null
    this._rejectDiskWaiters(accountingError('STORAGE_ACCOUNTING_STOPPED', 'Storage accounting stopped'))
    if (this._diskEpoch) await this._diskEpoch.stop()
    if (this._diskEpochPromise) await this._diskEpochPromise
    if (this._registryListenerAttached && typeof this.appRegistry.off === 'function') {
      this.appRegistry.off('change', this._onRegistryChange)
    }
    this._registryListenerAttached = false
    if (typeof this.appRegistry.releasePopulationConsumer === 'function') {
      this.appRegistry.releasePopulationConsumer('storage-accounting')
    }
    if (this._diskFailedDrain) {
      throw accountingError(
        'STORAGE_ACCOUNTING_FAILED_DRAIN',
        'Storage accounting epoch did not prove filesystem-handle drain',
        this._diskFailedDrain
      )
    }
  }

  /** Measure one entry's drive right now (used by eviction pre-checks). */
  async measure (appKeyHex) {
    if (this._stopping) return null
    const entry = this.appRegistry.get(appKeyHex)
    const drive = entry && entry.drive
    if (!drive) return null
    const meta = await coreStorageBytes(drive.core, this.infoTimeoutMs)
    const blobs = drive.blobs ? await coreStorageBytes(drive.blobs.core, this.infoTimeoutMs) : 0
    if (this._stopping) return null
    const rec = { bytes: meta + blobs, measuredAt: this._now() }
    this._bytes.set(appKeyHex, rec)
    return rec.bytes
  }

  /**
   * Join the one bounded on-disk accounting epoch. The epoch continues when a
   * caller's short waiter expires; another caller can attach but cannot bypass
   * its limits or the completion-based 30m+jitter gap.
   */
  async measureDisk (opts = {}) {
    if (!this.storagePath) return this._diskBytes
    if (this._stopping) throw accountingError('STORAGE_ACCOUNTING_STOPPED', 'Storage accounting stopped')
    if (this._diskFailedDrain) {
      throw accountingError('STORAGE_ACCOUNTING_FAILED_DRAIN', 'Prior accounting epoch did not drain', this._diskFailedDrain)
    }
    const timeoutMs = positiveDeadline(opts.timeoutMs, DISK_WAITER_DEFAULT_MS, DISK_WAITER_MAX_MS, 'measureDisk timeout')
    if (this._diskEpochPromise) this._diskStats.coalesced++
    if (!this._diskEpochPromise && this._now() >= this._diskNextDueAt) this._startDiskEpoch()
    else if (!this._diskEpochPromise && this._started) this._scheduleDiskEpoch(this._diskNextDueAt - this._now())
    return await this._attachDiskWaiter(timeoutMs)
  }

  _startDiskEpoch () {
    if (this._diskEpochPromise || this._stopping || this._diskFailedDrain || !this.storagePath) return
    if (this._diskTimer) this._clearTimeout(this._diskTimer)
    this._diskTimer = null
    const epoch = this._epochFactory(this.storagePath)
    if (!epoch || typeof epoch.run !== 'function' || typeof epoch.stop !== 'function') {
      throw new TypeError('StorageAccounting: epochFactory must return a StorageAccountingEpoch')
    }
    this._diskEpoch = epoch
    this._diskStats.epochsStarted++
    this._diskEpochPromise = Promise.resolve().then(() => epoch.run()).then(
      result => this._settleDiskEpoch(result),
      err => this._settleDiskEpoch({
        complete: false,
        bytes: null,
        observedAt: null,
        completedAt: null,
        finishedAt: this._now(),
        durationMs: null,
        incompleteReason: 'epoch-error',
        error: { code: err?.code || 'STORAGE_ACCOUNTING_EPOCH_ERROR', message: err?.message || String(err) },
        progress: null,
        operations: null,
        failedDrain: true
      })
    ).finally(() => {
      this._diskEpoch = null
      this._diskEpochPromise = null
      if (this._started && !this._stopping && !this._diskFailedDrain) {
        this._scheduleDiskEpoch(this._diskNextDueAt - this._now())
      }
    })
  }

  _settleDiskEpoch (result) {
    const complete = result && result.complete === true &&
      Number.isSafeInteger(result.bytes) && result.bytes >= 0 &&
      Number.isSafeInteger(result.observedAt) &&
      Number.isSafeInteger(result.completedAt) &&
      result.completedAt >= result.observedAt
    this._lastDiskAttempt = result && typeof result === 'object' ? Object.freeze({ ...result }) : null
    if (complete) {
      const sample = Object.freeze({
        bytes: result.bytes,
        observedAt: result.observedAt,
        completedAt: result.completedAt,
        durationMs: result.completedAt - result.observedAt,
        progress: result.progress || null,
        operations: result.operations || null
      })
      this._lastCompleteDiskSample = sample
      this._diskBytes = sample.bytes
      this._diskMeasurementComplete = true
      this._diskRetryMs = DISK_RETRY_MIN_MS
      const jitter = diskJitter(this._random)
      this._diskNextDueAt = sample.completedAt + DISK_SUCCESS_INTERVAL_MS + jitter
      this._diskStats.epochsCompleted++
      this._resolveDiskWaiters(sample.bytes)
    } else {
      this._diskMeasurementComplete = false
      this._diskStats.epochsFailed++
      if (result?.failedDrain === true) this._diskFailedDrain = result
      const finishedAt = Number.isSafeInteger(result?.finishedAt) ? result.finishedAt : this._now()
      const jitter = diskJitter(this._random)
      this._diskNextDueAt = finishedAt + this._diskRetryMs + jitter
      this._diskRetryMs = Math.min(DISK_RETRY_MAX_MS, this._diskRetryMs * 2)
      this._rejectDiskWaiters(accountingError(
        'STORAGE_ACCOUNTING_INCOMPLETE',
        'Storage accounting epoch was incomplete: ' + (result?.incompleteReason || 'unknown'),
        result || null
      ))
    }
    return result
  }

  _scheduleDiskEpoch (delayMs) {
    if (!this._started || this._stopping || this._diskFailedDrain || this._diskEpochPromise) return
    if (this._diskTimer) this._clearTimeout(this._diskTimer)
    const delay = Math.max(0, Number.isFinite(delayMs) ? delayMs : 0)
    this._diskTimer = this._setTimeout(() => {
      this._diskTimer = null
      try {
        this._startDiskEpoch()
      } catch (err) {
        this.emit('error', err)
      }
    }, delay)
    if (this._diskTimer && this._diskTimer.unref) this._diskTimer.unref()
  }

  _attachDiskWaiter (timeoutMs) {
    if (this._diskWaiters.size >= DISK_MAX_WAITERS) {
      this._diskStats.waiterOverflow++
      return Promise.reject(accountingError(
        'STORAGE_ACCOUNTING_BUSY',
        'Storage accounting waiter limit reached',
        { limit: DISK_MAX_WAITERS }
      ))
    }
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: null }
      waiter.timer = this._setTimeout(() => {
        if (!this._diskWaiters.delete(waiter)) return
        this._diskStats.waiterTimeouts++
        reject(accountingError(
          'STORAGE_ACCOUNTING_TIMEOUT',
          'Storage accounting waiter deadline elapsed',
          { timeoutMs }
        ))
      }, timeoutMs)
      this._diskWaiters.add(waiter)
    })
  }

  _resolveDiskWaiters (value) {
    for (const waiter of this._diskWaiters) {
      this._clearTimeout(waiter.timer)
      waiter.resolve(value)
    }
    this._diskWaiters.clear()
  }

  _rejectDiskWaiters (err) {
    for (const waiter of this._diskWaiters) {
      this._clearTimeout(waiter.timer)
      waiter.reject(err)
    }
    this._diskWaiters.clear()
  }

  async _tick () {
    if (this._stopping) return { complete: true, examined: 0, stopped: true }
    if (this._sweeping) return { complete: false, examined: 0, coalesced: true }
    if (typeof this.appRegistry.page !== 'function') {
      throw new TypeError('StorageAccounting: appRegistry.page is required for bounded accounting')
    }
    this._attachRegistryListener()
    this._sweeping = true
    try {
      const page = this.appRegistry.page('storage-accounting', this.batchSize)
      for (const item of page.entries) {
        const bytes = await this.measure(item.key)
        if (bytes !== null) {
          const rec = this._bytes.get(item.key)
          retainTopEntry(this._topWorking, {
            appKey: item.key,
            bytes,
            measuredAt: rec?.measuredAt ?? this._now()
          })
        }
      }
      if (page.complete) {
        this._topPublished = this._topWorking.map(row => ({ ...row }))
        this._topWorking = []
        this._fullSweeps++
        this._lastFullSweepAt = this._now()
      }
      return page
    } finally {
      this._sweeping = false
    }
  }

  /**
   * Register an external byte source counted alongside the appRegistry drives.
   * `fn` is a synchronous () => number (bytes). Used by the shard-store so its
   * dedicated-hypercore bytes are visible to the storage guards (STO-005).
   * Re-registering the same name replaces the callback.
   */
  registerExternalSource (name, fn) {
    if (!name || typeof fn !== 'function') throw new Error('registerExternalSource: name + fn required')
    this._sources.set(name, fn)
  }

  unregisterExternalSource (name) {
    this._sources.delete(name)
  }

  /** Sum of all registered external sources (bytes), robust to a throwing fn. */
  sourceBytes () {
    let total = 0
    for (const fn of this._sources.values()) {
      try {
        const v = Number(fn())
        if (Number.isFinite(v) && v > 0) total += v
      } catch { /* a broken source counts as 0, never crashes accounting */ }
    }
    return total
  }

  getBytes (appKeyHex) {
    const rec = this._bytes.get(appKeyHex)
    return rec ? rec.bytes : null
  }

  /** Largest measured entries first — eviction's ranking input. */
  getTop (n = 20) {
    const limit = strictPositiveInteger(n, 'StorageAccounting getTop limit', MAX_TOP_ENTRIES)
    return this._topPublished.slice(0, limit).map(row => ({ ...row }))
  }

  getSummary () {
    const perEntry = this._bytes.totalBytes
    const sourceBytes = this.sourceBytes()
    // Authoritative total = the measured on-disk footprint when available
    // (catches bare/lazy cores the per-entry walk misses); the per-entry sum
    // plus registered external sources (e.g. shard-store bytes) is only ever a
    // subset, so max() is a safe floor before the first du. Using max() also
    // means shard bytes already captured by the du of storagePath are never
    // double-counted (STO-005).
    const measured = perEntry + sourceBytes
    const totalBytes = this._diskBytes != null ? Math.max(this._diskBytes, measured) : measured
    const sample = this._lastCompleteDiskSample
    const attempt = this._lastDiskAttempt
    return {
      totalBytes,
      diskBytes: this._diskBytes,
      perEntryBytes: perEntry,
      sourceBytes,
      // diskMeasuredAt remains an observedAt alias for old dashboards. RC9
      // receipt and capacity paths consume the explicit immutable pair.
      diskMeasuredAt: sample?.observedAt ?? null,
      diskObservedAt: sample?.observedAt ?? null,
      diskCompletedAt: sample?.completedAt ?? null,
      diskMeasureDurationMs: sample?.durationMs ?? null,
      diskIntervalMs: DISK_SUCCESS_INTERVAL_MS + DISK_SUCCESS_JITTER_MS,
      diskMeasurementComplete: this._diskMeasurementComplete === true,
      diskIncompleteReason: this._diskMeasurementComplete ? null : (attempt?.incompleteReason ?? null),
      diskProgress: this._diskEpoch?.getProgress?.() || attempt?.progress || sample?.progress || null,
      diskOperations: attempt?.operations || sample?.operations || null,
      diskNextDueAt: this._diskNextDueAt || null,
      diskFailedDrain: this._diskFailedDrain !== null,
      diskWaiters: this._diskWaiters.size,
      diskEpochActive: this._diskEpochPromise !== null,
      diskEpochStats: Object.freeze({ ...this._diskStats }),
      entryScheduler: this._entryScheduler?.snapshot() || null,
      measuredEntries: this._bytes.size,
      fullSweeps: this._fullSweeps,
      lastFullSweepAt: this._lastFullSweepAt
    }
  }

  /**
   * Fixed-shape runtime diagnostics. Unlike getSummary(), this never sums the
   * per-drive byte map or invokes an external byte source.
   */
  getResourceDiagnostics () {
    const progress = this._diskEpoch && typeof this._diskEpoch.getProgress === 'function'
      ? this._diskEpoch.getProgress()
      : null
    const attempt = this._lastDiskAttempt
    const sample = this._lastCompleteDiskSample
    const observedAt = attempt?.observedAt ?? sample?.observedAt ?? null
    const completedAt = attempt?.completedAt ?? sample?.completedAt ?? null
    const now = this._now()
    return {
      available: true,
      epochActive: this._diskEpochPromise !== null,
      state: progress?.state || (this._diskFailedDrain ? 'failed-drain' : 'idle'),
      waiters: this._diskWaiters.size,
      measuredEntries: this._bytes.size,
      operationsInFlight: progress?.operationsInFlight ?? 0,
      queuedPaths: progress?.queuedPaths ?? 0,
      queuedPathBytes: progress?.queuedPathBytes ?? 0,
      bookkeepingBytes: progress?.bookkeepingBytes ?? 0,
      observedAt,
      completedAt,
      ageMs: Number.isSafeInteger(observedAt) && Number.isSafeInteger(now)
        ? Math.max(0, now - observedAt)
        : null,
      lastDurationMs: attempt?.durationMs ?? sample?.durationMs ?? null,
      incompleteReason: this._diskMeasurementComplete ? null : (attempt?.incompleteReason ?? null),
      nextDueAt: this._diskNextDueAt || null,
      epochsStarted: this._diskStats.epochsStarted,
      epochsCompleted: this._diskStats.epochsCompleted,
      epochsFailed: this._diskStats.epochsFailed,
      coalesced: this._diskStats.coalesced,
      waiterTimeouts: this._diskStats.waiterTimeouts,
      waiterOverflow: this._diskStats.waiterOverflow
    }
  }
}
