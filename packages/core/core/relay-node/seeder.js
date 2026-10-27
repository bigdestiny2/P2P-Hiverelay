import b4a from 'b4a'
import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'

const PERSIST_SCHEMA_VERSION = 1
const HEX64_RE = /^[0-9a-f]{64}$/i

// lastServedAt moves on every served block; persist it at most this often so
// the eviction LRU order survives a restart without turning uploads into
// disk writes.
const SERVED_PERSIST_INTERVAL_MS = 10 * 60 * 1000
// info({ storage: true }) stat()s four files per core. A core damaged by a
// disk-full crash can wedge that await; a slow measurement must cost seconds,
// not the pin (same guard as StorageAccounting).
const DEFAULT_MEASURE_TIMEOUT_MS = 8_000
// Keys dropped for exceeding their bound, remembered with the size we saw, so
// a publisher that keeps re-sending the same request can't make us re-download
// and re-purge the same oversize core forever. In-memory, FIFO-capped.
const OVERSIZE_MEMO_MAX = 1024

// Pin provenance (v0.24.5) — decides what the disk-pressure sweep may shed.
//   'seed-request' admitted from a P2P seed request under a publisher budget.
//   'local'        operator /seed-core, catalog bee, relay-internal callers
//                  (outboxlog journal). Sacred to the sweep, like archive tier.
//   'legacy'       restored from a pre-v0.24.5 bare string entry: origin and
//                  pin time unknown. On the fleet these are overwhelmingly
//                  seed-request video pins, so the sweep treats them as
//                  evictable (catalog bee + writable cores stay exempt).
const PIN_SOURCES = new Set(['seed-request', 'local', 'legacy'])

function seedError (code, message) {
  const err = new Error(message)
  err.code = code
  return err
}

function positiveBytes (v) {
  const n = Number(v)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null
}

// Logical size of a pinned core once we have seen its length (after an
// upgrade, or from local storage on restart). null while unknown — a freshly
// opened remote core reports length 0 until a peer tells us otherwise.
function knownByteLength (core) {
  if (!core || !(core.length > 0)) return null
  const n = Number(core.byteLength)
  return Number.isFinite(n) && n >= 0 ? n : null
}

function normalizePinRecord (p) {
  if (!p || typeof p !== 'object' || typeof p.key !== 'string' || !HEX64_RE.test(p.key)) return null
  return {
    key: p.key.toLowerCase(),
    maxStorageBytes: positiveBytes(p.maxStorageBytes),
    group: typeof p.group === 'string' && p.group.length > 0 && p.group.length <= 128 ? p.group : null,
    source: PIN_SOURCES.has(p.source) ? p.source : 'legacy',
    pinnedAt: Number.isFinite(p.pinnedAt) && p.pinnedAt >= 0 ? p.pinnedAt : 0,
    lastServedAt: Number.isFinite(p.lastServedAt) && p.lastServedAt >= 0 ? p.lastServedAt : 0
  }
}

function legacyPinRecord (key) {
  if (typeof key !== 'string' || !HEX64_RE.test(key)) return null
  // pinnedAt 0 = "pinned before v0.24.5 recorded pin times" — treated as old
  // by the sweep's minAgeMs gate, so a full disk can shed legacy pins at once.
  return { key: key.toLowerCase(), maxStorageBytes: null, group: null, source: 'legacy', pinnedAt: 0, lastServedAt: 0 }
}

export class Seeder extends EventEmitter {
  /**
   * @param {object} store  corestore
   * @param {object} swarm  hyperswarm (join/leave)
   * @param {object} [opts]
   * @param {number} [opts.maxStorageBytes]   relay cap; also the default per-core bound
   * @param {number} [opts.announceInterval]
   * @param {string} [opts.storagePath]       seeded-cores.json path (null = no persistence)
   * @param {function} [opts.getAvailableBytes] () => number — relay-wide room left (cap AND
   *   physical-disk headroom), already net of every reservation. The node wires its
   *   _availableStorageBytes(); standalone the seeder only knows its own pins.
   * @param {function} [opts.groupBaseBytes]  (groupId) => number — bytes a budget group
   *   already uses outside the seeder (the seed request's app drive).
   * @param {function} [opts.isProtectedCore] (hex) => boolean — never purge/evict
   *   (catalog bee, a live app drive's core).
   * @param {number} [opts.measureTimeoutMs]
   */
  constructor (store, swarm, opts = {}) {
    super()
    this.store = store
    this.swarm = swarm
    this.maxStorageBytes = opts.maxStorageBytes || 50 * 1024 * 1024 * 1024
    this.announceInterval = opts.announceInterval || 15 * 60 * 1000
    this.cores = new Map() // hex key -> entry (see _createEntry)
    // Restart-safe since v0.24.5: each pin's bytes are measured from storage
    // on ready() and grown by 'download' events, so this is the real on-disk
    // size of the bare pins (it used to restart at ~0, which let 40+ GB of
    // pinned video sit outside the cap).
    this.totalBytesStored = 0
    this.totalBytesServed = 0
    this.running = false

    this._getAvailableBytes = typeof opts.getAvailableBytes === 'function' ? opts.getAvailableBytes : null
    this._groupBaseBytes = typeof opts.groupBaseBytes === 'function' ? opts.groupBaseBytes : null
    this._isProtectedCore = typeof opts.isProtectedCore === 'function' ? opts.isProtectedCore : null
    this.measureTimeoutMs = Number.isFinite(opts.measureTimeoutMs) ? Math.max(50, opts.measureTimeoutMs) : DEFAULT_MEASURE_TIMEOUT_MS
    // Pins whose core.ready() is still in flight. Their reservations already
    // count (see pendingBytes) so concurrent admissions can't double-book.
    this._opening = new Map() // hex -> { entry, promise }
    this._oversize = new Map() // hex -> byteLength seen when dropped for its bound
    // Persisted records not (yet) active: queued for restore, or whose restore
    // failed for a non-bound reason. Written back with every persist so a write
    // mid-restore (a bound drop) or a transient open error never forgets them.
    this._carry = new Map() // hex -> record
    this._lastServedPersistAt = 0
    this._stopped = false

    // v0.18.x — persist the set of seeded BARE-core keys so they survive a
    // relay restart. Catalog bees + any /seed-core pin are plain Hypercores
    // (not appRegistry-managed Hyperdrives), so without this they'd be
    // forgotten on restart and the relay would silently stop serving them.
    // Atomic tmp+rename (same pattern as subsidy.json / lease.json).
    this._persistPath = opts.storagePath || null
    this._persistTail = Promise.resolve()
    // True while start() re-seeds the persisted list (kept for observers;
    // restore calls pass _restore so concurrent new pins still persist).
    this._restoring = false
  }

  async start () {
    this.running = true
    this._stopped = false
    // Re-seed cores pinned in a previous run. Their blocks already live in the
    // corestore on disk, so this re-opens + re-announces them (fast) and
    // resumes serving. Per-key failures are non-fatal.
    await this._restorePersisted()
    this.emit('started')
  }

  /**
   * Pin a bare Hypercore by public key: download it and keep announcing it.
   *
   * Bounds (v0.24.5). A pin can never grow past its bound: once the core's
   * byteLength is known (at ready(), or when an upgrade lands) and exceeds
   * it, the download stops and the core is unseeded AND purged, with a
   * 'core-bound-exceeded' event.
   *
   * @param {string} publicKeyHex
   * @param {object} [opts]
   * @param {number} [opts.maxStorageBytes] Bound in logical bytes. When given, the
   *   pin also RESERVES that much capacity up front and is refused
   *   (INSUFFICIENT_STORAGE) when the relay can't fit it. When omitted — the
   *   operator/internal paths: /seed-core + catalog bee, outboxlog journal,
   *   restore of legacy entries — the bound defaults to the relay cap
   *   (this.maxStorageBytes, read live) with no up-front reservation: a core
   *   bigger than the whole relay budget can never fit, so the default only
   *   excludes that pathological case, and the pin is refused only when the
   *   relay is already full.
   * @param {string} [opts.group] Budget group for cores admitted together (a
   *   seed request: its app key). maxStorageBytes is then the group's
   *   AGGREGATE budget — the group's cores plus groupBaseBytes(group) must fit
   *   in it together — and the reservation is taken once per group.
   * @param {string} [opts.source] 'seed-request' | 'local' (default)
   * @returns {Promise<object>} the pin entry
   */
  async seedCore (publicKeyHex, opts = {}) {
    const existing = this.cores.get(publicKeyHex)
    if (existing) return existing
    const opening = this._opening.get(publicKeyHex)
    if (opening) return opening.promise

    const entry = this._createEntry(publicKeyHex, opts)
    // Admission runs synchronously (before the first await) and the
    // reservation is registered in the same tick, so the very next capacity
    // check already sees it — RelayNode admits a whole request's cores in one
    // synchronous loop.
    this._admit(entry, opts)
    const slot = { entry, promise: null }
    this._opening.set(publicKeyHex, slot)
    slot.promise = this._openEntry(entry, opts)
    return slot.promise
  }

  _createEntry (publicKeyHex, opts) {
    const bound = positiveBytes(opts.maxStorageBytes)
    return {
      core: null,
      range: null,
      interval: null,
      topic: null,
      publicKeyHex,
      startedAt: Date.now(),
      bytesStored: 0,
      bytesServed: 0,
      // null -> default bound (relay cap, read live at check time)
      maxStorageBytes: bound,
      // An explicit bound is a publisher budget: reserve it until the real
      // size is known (pendingBytes).
      reserve: bound != null,
      group: typeof opts.group === 'string' && opts.group.length > 0 ? opts.group : null,
      source: PIN_SOURCES.has(opts.source) ? opts.source : 'local',
      pinnedAt: Number.isFinite(opts.pinnedAt) ? opts.pinnedAt : Date.now(),
      lastServedAt: Number.isFinite(opts.lastServedAt) ? opts.lastServedAt : 0,
      knownByteLength: null,
      writable: false,
      dropping: false,
      released: false
    }
  }

  _boundOf (entry) {
    return entry.maxStorageBytes != null ? entry.maxStorageBytes : this.maxStorageBytes
  }

  _admit (entry, opts) {
    // A restored pin's bytes are already on disk; refusing it would only
    // forget data we hold (its bound is still enforced once it opens).
    if (opts._restore) return

    // Later cores of a budget group (the same app's next request) share the
    // budget the group's first core reserved. A larger budget raises it for
    // the whole group, reserving only the delta; a smaller one is ignored —
    // a re-request (e.g. an SDK default) must never purge pins already held.
    let groupBudget = null
    let raise = 0
    if (entry.reserve && entry.group) {
      groupBudget = this._groupBudget(entry.group)
      if (groupBudget != null) {
        if (entry.maxStorageBytes > groupBudget) raise = entry.maxStorageBytes - groupBudget
        else entry.maxStorageBytes = groupBudget
      }
    }

    const seen = this._oversize.get(entry.publicKeyHex)
    if (seen != null && this._exceedsBound(entry, seen)) {
      throw seedError('BOUND_EXCEEDED', 'core ' + entry.publicKeyHex.slice(0, 16) + ' (' + seen + ' bytes) does not fit its ' + this._boundOf(entry) + '-byte bound')
    }

    // Unreserved (local) pins are checked after ready(), once writability is
    // known.
    if (!entry.reserve) return
    const need = groupBudget != null ? raise : entry.maxStorageBytes
    if (need > 0) {
      const available = this.availableBytes()
      if (available < need) {
        throw seedError('INSUFFICIENT_STORAGE', 'relay has ' + Math.max(0, available) + ' bytes available, pin needs ' + need)
      }
    }
    if (raise > 0) {
      for (const e of this._entries()) {
        if (e.group === entry.group && e.reserve) e.maxStorageBytes = entry.maxStorageBytes
      }
    }
  }

  // The shared budget of an active group, or null when no member is pinned.
  _groupBudget (group) {
    let budget = null
    for (const e of this._entries()) {
      if (e.group === group && e.reserve && !e.dropping) budget = Math.max(budget || 0, e.maxStorageBytes)
    }
    return budget
  }

  // Active pins plus those still opening.
  * _entries () {
    yield * this.cores.values()
    for (const slot of this._opening.values()) yield slot.entry
  }

  async _openEntry (entry, opts) {
    const hex = entry.publicKeyHex
    try {
      entry.core = this.store.get({ key: b4a.from(hex, 'hex') })
      await entry.core.ready()
      if (this._stopped) throw seedError('SEEDER_STOPPED', 'seeder stopped while opening ' + hex.slice(0, 16))
      entry.writable = entry.core.writable === true
      entry.knownByteLength = knownByteLength(entry.core)
      // Restart-safe accounting: start from what is actually on disk for
      // this core instead of 0, then grow with 'download' events.
      entry.bytesStored = await this._measureStored(entry.core)
      if (this._stopped) throw seedError('SEEDER_STOPPED', 'seeder stopped while opening ' + hex.slice(0, 16))
      // Local pins: refuse only when the relay is already full. Writable
      // cores are our own data (outboxlog journal) — their bytes exist
      // whether or not we announce them, so they are never refused.
      if (!opts._restore && !entry.reserve && !entry.writable && !this.hasCapacity(0)) {
        throw seedError('INSUFFICIENT_STORAGE', 'relay storage is full (' + Math.max(0, this.availableBytes()) + ' bytes available)')
      }
    } catch (err) {
      this._opening.delete(hex)
      if (entry.core) { try { await entry.core.close() } catch (_) {} }
      throw err
    }

    // Promote opening -> active in one tick so pendingBytes never sees it twice.
    this._opening.delete(hex)
    this._carry.delete(hex)
    this.cores.set(hex, entry)
    this.totalBytesStored += entry.bytesStored

    // A bound already exceeded at open (size known from local storage, or an
    // upgrade that landed while we measured) is enforced before downloading.
    if (await this._enforceBound(entry)) {
      throw seedError('BOUND_EXCEEDED', 'core ' + hex.slice(0, 16) + ' exceeds its storage bound')
    }

    this._startServing(entry)
    // Persist the new pin so it's re-seeded after a restart (a restore is
    // re-reading exactly this file, so it skips the write).
    if (!opts._restore) this._persist()
    this.emit('seeding-core', { publicKeyHex: hex, length: entry.core.length })
    return entry
  }

  _startServing (entry) {
    const core = entry.core
    const hex = entry.publicKeyHex

    const onSize = () => {
      const size = knownByteLength(core)
      if (size === entry.knownByteLength) return
      entry.knownByteLength = size
      this._enforceBound(entry).catch((err) => {
        this.emit('bound-check-error', { publicKeyHex: hex, error: err && err.message ? err.message : String(err) })
      })
    }

    // Track storage as blocks download
    core.on('download', (index, byteLength) => {
      if (entry.released) return
      entry.bytesStored += byteLength
      this.totalBytesStored += byteLength
      this.emit('block-downloaded', { publicKeyHex: hex, index, byteLength })
      // Cheap compare; catches a length learned between ready() and here.
      onSize()
    })

    core.on('upload', (index, byteLength) => {
      entry.bytesServed += byteLength
      this.totalBytesServed += byteLength
      entry.lastServedAt = Date.now()
      this.emit('block-served', { publicKeyHex: hex, index, byteLength })
      this._maybePersistServed(entry.lastServedAt)
    })

    // Sparse sessions emit 'append' when an upgrade lands — i.e. as soon as
    // a peer tells us the core's length, before most blocks arrive. That is
    // when an oversize core is caught, so little is downloaded before purge.
    core.on('append', onSize)
    core.on('truncate', onSize)

    // Download all blocks (end -1 is a live range: it follows appends and
    // never resolves on its own)
    entry.range = core.download({ start: 0, end: -1 })
    entry.range.done().catch((err) => {
      // Log but don't throw — download will retry
      if (!entry.released) this.emit('download-error', { key: hex, error: err && err.message })
    })

    // Periodically re-announce on the DHT, and re-sync the byte count with
    // storage ('download' events count payload only, not tree/oplog).
    entry.topic = core.discoveryKey
    this.swarm.join(entry.topic, { server: true, client: true })

    entry.interval = setInterval(() => {
      if (this.running) {
        this.swarm.join(entry.topic, { server: true, client: true })
        this._remeasure(entry).catch(() => {})
      }
    }, this.announceInterval)
    if (entry.interval.unref) entry.interval.unref()
  }

  // Over its own bound, or (budget groups) the group's cores + base bytes over
  // the shared budget? Our own writable cores are never dropped for size.
  // `size` overrides the entry's known size (admission's oversize memo).
  _exceedsBound (entry, size = entry.knownByteLength) {
    if (entry.writable) return null
    if (size == null) return null
    const bound = this._boundOf(entry)
    if (size > bound) return { reason: 'core-bound', byteLength: size, limit: bound, groupBytes: null }
    if (entry.group && entry.reserve) {
      let total = this._groupBase(entry.group)
      for (const e of this._entries()) {
        if (e !== entry && e.group === entry.group && !e.dropping) total += e.knownByteLength || 0
      }
      total += size
      if (total > entry.maxStorageBytes) {
        return { reason: 'group-budget', byteLength: size, limit: entry.maxStorageBytes, groupBytes: total }
      }
    }
    return null
  }

  _groupBase (group) {
    if (!this._groupBaseBytes) return 0
    try {
      const n = Number(this._groupBaseBytes(group))
      return Number.isFinite(n) && n > 0 ? n : 0
    } catch (_) {
      return 0
    }
  }

  async _enforceBound (entry) {
    if (entry.dropping) return true
    const over = this._exceedsBound(entry)
    if (!over) return false
    entry.dropping = true
    this._rememberOversize(entry.publicKeyHex, over.byteLength)
    const res = await this.unseedCore(entry.publicKeyHex, { reason: 'bound-exceeded' })
    this.emit('core-bound-exceeded', {
      publicKeyHex: entry.publicKeyHex,
      group: entry.group,
      source: entry.source,
      reason: over.reason,
      byteLength: over.byteLength,
      maxStorageBytes: over.limit,
      groupBytes: over.groupBytes,
      freedBytes: res.freedBytes,
      purged: res.purged
    })
    return true
  }

  _rememberOversize (hex, byteLength) {
    this._oversize.delete(hex)
    this._oversize.set(hex, byteLength)
    while (this._oversize.size > OVERSIZE_MEMO_MAX) {
      this._oversize.delete(this._oversize.keys().next().value)
    }
  }

  _protected (hex) {
    if (!this._isProtectedCore) return false
    try { return this._isProtectedCore(hex) === true } catch (_) { return true }
  }

  // Allocated on-disk bytes of one core (oplog + tree + blocks + bitfield,
  // st.blocks*512 — what du/df see). hypercore 10.38 exposes this via
  // info({ storage: true }); storage without stat() (e.g. RAM) yields null,
  // in which case we estimate from the contiguous prefix.
  async _measureStored (core) {
    if (!core || typeof core.info !== 'function') return 0
    let timer = null
    try {
      const info = await Promise.race([
        core.info({ storage: true }),
        new Promise((resolve) => { timer = setTimeout(resolve, this.measureTimeoutMs, null) })
      ])
      const s = info && info.storage
      if (s) return (s.oplog || 0) + (s.tree || 0) + (s.blocks || 0) + (s.bitfield || 0)
      if (info && info.length > 0 && info.contiguousLength > 0) {
        return Math.round(info.byteLength * Math.min(1, info.contiguousLength / info.length))
      }
      return 0
    } catch (_) {
      return 0
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  // Re-sync a pin's byte count with storage — 'download' events count
  // payload only, not tree/oplog.
  async _remeasure (entry) {
    if (entry.released || this.cores.get(entry.publicKeyHex) !== entry) return
    const before = entry.bytesStored
    const measured = await this._measureStored(entry.core)
    if (entry.released || measured <= 0) return
    // Apply as a delta so 'download' increments that landed during the
    // measurement are kept (errs toward over-counting, never under).
    const delta = measured - before
    entry.bytesStored = Math.max(0, entry.bytesStored + delta)
    this.totalBytesStored = Math.max(0, this.totalBytesStored + delta)
  }

  // Release a single entry's live resources WITHOUT touching the persisted
  // set. Shared by unseedCore (intentional removal) and stop() (teardown).
  async _releaseEntry (entry, { close = true } = {}) {
    entry.released = true
    if (entry.interval) clearInterval(entry.interval)
    if (entry.topic) { try { await this.swarm.leave(entry.topic) } catch (_) {} }
    if (entry.range) { try { entry.range.destroy() } catch (_) {} }
    if (close && entry.core) { try { await entry.core.close() } catch (_) {} }
  }

  /**
   * Intentional unseed: operator no longer wants this core, it outgrew its
   * bound, or the sweep evicted it. Removes it from the persisted set so it
   * is NOT re-seeded on the next start, and (v0.24.5) PURGES its storage so
   * the bytes actually return — closing alone left multi-GB video cores on
   * disk forever. hypercore 10.38's core.purge() closes every session on the
   * core and unlinks its oplog/tree/bitfield/blocks files.
   *
   * Never purged (released and kept on disk instead): writable cores (our
   * own data, e.g. the outboxlog journal — we may be the only copy) and
   * cores the node reports as protected (catalog bee, a live app drive's
   * core — purge would close the drive's sessions out from under it).
   *
   * @param {string} publicKeyHex
   * @param {object} [opts]
   * @param {boolean} [opts.purge=true]
   * @param {string} [opts.reason='unseed']
   * @returns {Promise<{ freedBytes: number, purged: boolean }>}
   */
  async unseedCore (publicKeyHex, opts = {}) {
    const entry = this.cores.get(publicKeyHex)
    if (!entry) {
      // A persisted pin that never opened this run: just forget it.
      if (this._carry.delete(publicKeyHex)) this._persist()
      return { freedBytes: 0, purged: false }
    }
    const reason = opts.reason || 'unseed'

    // Out of accounting and candidate lists before any await.
    this.cores.delete(publicKeyHex)
    entry.dropping = true
    this.totalBytesStored = Math.max(0, this.totalBytesStored - entry.bytesStored)

    let purged = false
    let freedBytes = 0
    const keep = entry.writable || this._protected(publicKeyHex)
    if (opts.purge !== false && !keep && entry.core && typeof entry.core.purge === 'function') {
      // Measure right before unlinking: that is what the purge returns.
      const onDisk = await this._measureStored(entry.core)
      await this._releaseEntry(entry, { close: false })
      try {
        await entry.core.purge()
        purged = true
        freedBytes = onDisk || entry.bytesStored
      } catch (err) {
        this.emit('purge-error', { publicKeyHex, error: err && err.message ? err.message : String(err) })
        try { await entry.core.close() } catch (_) {}
      }
    } else {
      await this._releaseEntry(entry)
      if (opts.purge !== false && keep) {
        this.emit('purge-skipped', { publicKeyHex, reason: entry.writable ? 'writable' : 'protected' })
      }
    }

    this._persist()
    this.emit('unseeded-core', { publicKeyHex, reason, freedBytes, purged })
    return { freedBytes, purged }
  }

  /**
   * Disk-pressure eviction hook (EvictionManager's bare-core pass). Refuses
   * writable and protected cores; otherwise unseeds + purges.
   */
  async evictCore (publicKeyHex) {
    const entry = this.cores.get(publicKeyHex)
    if (!entry) return { evicted: false, skipped: 'not-pinned', freedBytes: 0, purged: false }
    if (entry.writable) return { evicted: false, skipped: 'writable', freedBytes: 0, purged: false }
    if (this._protected(publicKeyHex)) return { evicted: false, skipped: 'protected', freedBytes: 0, purged: false }
    const res = await this.unseedCore(publicKeyHex, { reason: 'evicted' })
    return { evicted: true, ...res }
  }

  /** Snapshot of active pins for the eviction sweep / operators. */
  listPins () {
    const out = []
    for (const e of this.cores.values()) {
      if (e.dropping) continue
      out.push({
        key: e.publicKeyHex,
        bytesStored: e.bytesStored,
        byteLength: e.knownByteLength,
        maxStorageBytes: e.maxStorageBytes,
        group: e.group,
        source: e.source,
        pinnedAt: e.pinnedAt,
        lastServedAt: e.lastServedAt,
        writable: e.writable
      })
    }
    return out
  }

  /**
   * Capacity promised to pins but not yet on disk. Budgeted pins reserve
   * their group budget until every member's size is known, then just the
   * known sizes (never more than the budget); unbudgeted pins count only
   * their known outstanding bytes.
   */
  pendingBytes () {
    let pending = 0
    const groups = new Map()
    for (const e of this._entries()) {
      if (e.dropping) continue
      if (e.reserve) {
        const id = e.group || e.publicKeyHex
        let g = groups.get(id)
        if (!g) {
          g = { budget: 0, known: 0, unknown: false, stored: 0 }
          groups.set(id, g)
        }
        g.budget = Math.max(g.budget, e.maxStorageBytes)
        if (e.knownByteLength == null) g.unknown = true
        else g.known += e.knownByteLength
        g.stored += e.bytesStored
      } else if (e.knownByteLength != null && e.knownByteLength > e.bytesStored) {
        pending += e.knownByteLength - e.bytesStored
      }
    }
    for (const g of groups.values()) {
      const target = g.unknown ? g.budget : Math.min(g.budget, g.known)
      pending += Math.max(0, target - g.stored)
    }
    return pending
  }

  /** Stored pin bytes plus outstanding reservations. */
  committedBytes () {
    return this.totalBytesStored + this.pendingBytes()
  }

  /** Room left for new pins (relay-wide when the node wires getAvailableBytes). */
  availableBytes () {
    if (this._getAvailableBytes) {
      const v = Number(this._getAvailableBytes())
      if (Number.isFinite(v)) return v
    }
    return this.maxStorageBytes - this.committedBytes()
  }

  hasCapacity (additionalBytes = 0) {
    const available = this.availableBytes()
    return additionalBytes > 0 ? available >= additionalBytes : available > 0
  }

  getStats () {
    return {
      coresSeeded: this.cores.size,
      totalBytesStored: this.totalBytesStored,
      totalBytesServed: this.totalBytesServed,
      pendingBytes: this.pendingBytes(),
      capacityUsedPct: Math.round((this.totalBytesStored / this.maxStorageBytes) * 100)
    }
  }

  async stop () {
    this.running = false
    this._stopped = true
    // Teardown only — release resources but DO NOT mutate the persisted set,
    // so a restart re-seeds exactly what was pinned. (A persisting unseed here
    // would empty the list on every graceful shutdown.)
    for (const slot of this._opening.values()) {
      if (slot.entry.core) { try { await slot.entry.core.close() } catch (_) {} }
    }
    for (const entry of this.cores.values()) {
      await this._releaseEntry(entry)
    }
    this.cores.clear()
    this.emit('stopped')
  }

  // ─── Persistence (atomic tmp+rename) ───────────────────────────────

  async _restorePersisted () {
    const records = await this._loadPersisted()
    if (!records.length) return
    this._restoring = true
    for (const r of records) this._carry.set(r.key, r)
    let restored = 0
    for (const r of records) {
      try {
        await this.seedCore(r.key, {
          maxStorageBytes: r.maxStorageBytes,
          group: r.group,
          source: r.source,
          pinnedAt: r.pinnedAt,
          lastServedAt: r.lastServedAt,
          _restore: true
        })
        restored++
      } catch (err) {
        // Dropped for its bound: purged on purpose, forget it. Anything else
        // (a damaged/wedged core) stays carried and is retried next start.
        if (err && err.code === 'BOUND_EXCEEDED') this._carry.delete(r.key)
        this.emit('reseed-error', { publicKeyHex: r.key, error: err && err.message ? err.message : String(err) })
      }
    }
    this._restoring = false
    if (restored) this.emit('cores-restored', { count: restored })
  }

  _maybePersistServed (now) {
    if (now - this._lastServedPersistAt < SERVED_PERSIST_INTERVAL_MS) return
    this._lastServedPersistAt = now
    this._persist()
  }

  _persist () {
    if (!this._persistPath) return
    this._persistTail = this._persistTail.then(() => this._writePersisted()).catch(() => {})
    return this._persistTail
  }

  // Format (schemaVersion 1, extended backward-compatibly in v0.24.5):
  //   { schemaVersion: 1,
  //     cores: [hex, ...],                       // pre-v0.24.5 shape, kept so a
  //                                              // rollback still restores every pin
  //     pins:  [{ key, maxStorageBytes, group, source, pinnedAt, lastServedAt }] }
  async _writePersisted () {
    const tmp = this._persistPath + '.tmp'
    const pins = []
    for (const e of this.cores.values()) {
      if (e.dropping) continue
      pins.push({
        key: e.publicKeyHex,
        maxStorageBytes: e.maxStorageBytes,
        group: e.group,
        source: e.source,
        pinnedAt: e.pinnedAt,
        lastServedAt: e.lastServedAt
      })
    }
    for (const [key, r] of this._carry) {
      if (!this.cores.has(key)) pins.push({ ...r })
    }
    const data = JSON.stringify({
      schemaVersion: PERSIST_SCHEMA_VERSION,
      cores: pins.map(p => p.key),
      pins
    })
    try {
      await mkdir(dirname(this._persistPath), { recursive: true })
      await this._writeTmp(tmp, data)
      // rename() is atomic: the previous file stays intact until the new
      // one is complete, so a failed write (ENOSPC on a full disk) can
      // never leave seeded-cores.json missing or truncated.
      await rename(tmp, this._persistPath)
    } catch (err) {
      try { await unlink(tmp) } catch (_) {}
      this.emit('persist-error', err)
    }
  }

  // Seam for tests (simulated ENOSPC).
  async _writeTmp (tmp, data) {
    await writeFile(tmp, data)
  }

  async _loadPersisted () {
    if (!this._persistPath) return []
    let data
    try {
      data = JSON.parse(await readFile(this._persistPath, 'utf8'))
    } catch {
      // Missing/corrupt -> nothing to restore. A lost list only means the
      // operator must re-pin; no data is destroyed (blocks stay in the store).
      return []
    }
    if (!data || data.schemaVersion !== PERSIST_SCHEMA_VERSION) return []
    const byKey = new Map()
    // v0.24.5+ records carry bounds + LRU metadata and win over `cores`.
    for (const p of (Array.isArray(data.pins) ? data.pins : [])) {
      const r = normalizePinRecord(p)
      if (r && !byKey.has(r.key)) byKey.set(r.key, r)
    }
    // `cores`: bare hex strings (pre-v0.24.5, and still written for
    // rollback) become legacy pins; object entries are accepted too.
    for (const c of (Array.isArray(data.cores) ? data.cores : [])) {
      const r = typeof c === 'string' ? legacyPinRecord(c) : normalizePinRecord(c)
      if (r && !byKey.has(r.key)) byKey.set(r.key, r)
    }
    return [...byKey.values()]
  }
}
