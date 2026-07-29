// served-accounting.js — honest outbound (served) byte counting.
//
// seeder.totalBytesServed only sums uploads from cores routed through
// Seeder.seedCore. On a real registry-drive relay that's just the
// seeding-registry log core, so the counter reads ~0 while the relay is
// actively serving app blocks — actual block serving flows through the
// corestore's `store.replicate(conn)` over appRegistry-managed Hyperdrives,
// which the seeder never attaches an 'upload' listener to. This is the
// served-bytes twin of the "Stored: 0 B" blind spot StorageAccounting fixed
// for stored bytes (2026-06-11 disk fill).
//
// Served bytes are a *flow*, not a measurable disk *state*: you cannot
// stat() the served total, you can only accumulate it as blocks go out. So
// this module attaches an upload observer to EVERY core the corestore
// opens — registry log + every drive's meta/blob core — and sums the byte
// lengths. Corestore 6 fired 'core-open' and exposed open cores as a Map;
// corestore 7 replaces both with a CoreTracker (store.cores.map) and
// store.watch(fn), and the tracked objects are internal Cores (not
// EventEmitters), so attach is mechanism-dependent (see _attach). A WeakSet
// guards against any double-attach, so each core is counted exactly once. The total is cumulative for the corestore's lifetime, mirroring the
// Prometheus hiverelay_bytes_served counter but measured at the replication
// layer instead of the seeder.

import { EventEmitter } from 'events'

export class ServedAccounting extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.store) throw new Error('ServedAccounting: store is required')
    this.store = opts.store
    this.totalBytesServed = 0
    this.totalBlocksServed = 0
    this._tracked = new WeakSet()
    this._listeners = new Set()
    this._coreCount = 0
    this._started = false
    this._onCoreOpen = (core) => this._attach(core)
  }

  start () {
    if (this._started) return
    this._started = true
    // Attach to cores already open when we start (the registry log core, any
    // drives reseeded before this point), then to every core opened later.
    // The store is shared across namespaces, so the tracked set holds every
    // core regardless of which namespace opened it.
    if (this.store.cores && typeof this.store.cores.values === 'function') {
      // corestore 6 (and test stubs): open cores are a plain Map.
      for (const core of this.store.cores.values()) this._attach(core)
    } else if (this.store.cores && this.store.cores.map instanceof Map) {
      // corestore 7: CoreTracker keeps internal Cores under .map.
      for (const core of this.store.cores.map.values()) this._attach(core)
    }
    if (typeof this.store.watch === 'function') {
      // corestore 7: watch(fn) fires with the internal Core on first open.
      this.store.watch(this._onCoreOpen)
    } else if (typeof this.store.on === 'function') {
      this.store.on('core-open', this._onCoreOpen)
    }
  }

  _attach (core) {
    if (!core || this._tracked.has(core)) return
    if (typeof core.on === 'function') {
      // Public session (or stub). Subscribing 'upload' auto-registers the
      // session as a replication monitor in hypercore 11 — same event the
      // Seeder reads; byteLength is the block payload (session padding
      // already subtracted by hypercore).
      this._tracked.add(core)
      this._coreCount++
      const onUpload = (index, byteLength) => {
        this.totalBytesServed += byteLength
        this.totalBlocksServed++
      }
      core.on('upload', onUpload)
      this._listeners.add({ core, onUpload })
    } else if (typeof core.addMonitor === 'function') {
      // corestore 7 internal Core: not an EventEmitter. Register a
      // lightweight replication monitor instead — the replicator emits
      // 'upload' to every monitor, so uploads are counted for all present
      // AND future sessions of the core. padding: 0 because the replicator
      // subtracts each monitor's own padding from the byte length (ours are
      // raw wire blocks; relay cores carry no session encryption padding).
      this._tracked.add(core)
      this._coreCount++
      const monitor = {
        _monitorIndex: -1,
        padding: 0,
        extensions: new Map(), // replicator also registers peer extensions from every monitor on peer-add
        emit: (name, index, byteLength) => {
          if (name !== 'upload') return
          this.totalBytesServed += byteLength
          this.totalBlocksServed++
        }
      }
      core.addMonitor(monitor)
      this._listeners.add({ core, monitor })
    }
  }

  getSummary () {
    return {
      totalBytesServed: this.totalBytesServed,
      totalBlocksServed: this.totalBlocksServed,
      trackedCores: this._coreCount
    }
  }

  stop () {
    if (!this._started) return
    this._started = false
    if (typeof this.store.unwatch === 'function') {
      this.store.unwatch(this._onCoreOpen)
    } else if (typeof this.store.removeListener === 'function') {
      this.store.removeListener('core-open', this._onCoreOpen)
    }
    for (const entry of this._listeners) {
      if (entry.onUpload && entry.core && typeof entry.core.removeListener === 'function') {
        entry.core.removeListener('upload', entry.onUpload)
      } else if (entry.monitor && entry.core && typeof entry.core.removeMonitor === 'function') {
        entry.core.removeMonitor(entry.monitor)
      }
    }
    this._listeners.clear()
    this._tracked = new WeakSet()
    this._coreCount = 0
  }
}
