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
// this module attaches an 'upload' listener to EVERY core the corestore
// opens — registry log + every drive's meta/blob core — and sums the byte
// lengths. Corestore fires 'core-open' once per distinct core (and a
// WeakSet guards against any double-attach), so each core is counted exactly
// once. The total is cumulative for the corestore's lifetime, mirroring the
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
    // The store is shared across namespaces (root.cores), so this set holds
    // every core regardless of which namespace opened it.
    if (this.store.cores && typeof this.store.cores.values === 'function') {
      for (const core of this.store.cores.values()) this._attach(core)
    }
    this.store.on('core-open', this._onCoreOpen)
  }

  _attach (core) {
    if (!core || this._tracked.has(core) || typeof core.on !== 'function') return
    this._tracked.add(core)
    this._coreCount++
    // Same event the Seeder reads (seeder.js) — byteLength is the served
    // block payload (padding already subtracted by hypercore).
    const onUpload = (index, byteLength) => {
      this.totalBytesServed += byteLength
      this.totalBlocksServed++
    }
    core.on('upload', onUpload)
    this._listeners.add({ core, onUpload })
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
    this.store.removeListener('core-open', this._onCoreOpen)
    for (const entry of this._listeners) {
      if (entry.core && typeof entry.core.removeListener === 'function') {
        entry.core.removeListener('upload', entry.onUpload)
      }
    }
    this._listeners.clear()
    this._tracked = new WeakSet()
    this._coreCount = 0
  }
}
