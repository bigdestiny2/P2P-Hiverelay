import b4a from 'b4a'
import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'

const PERSIST_SCHEMA_VERSION = 1

export class Seeder extends EventEmitter {
  constructor (store, swarm, opts = {}) {
    super()
    this.store = store
    this.swarm = swarm
    this.maxStorageBytes = opts.maxStorageBytes || 50 * 1024 * 1024 * 1024
    this.announceInterval = opts.announceInterval || 15 * 60 * 1000
    this.cores = new Map() // hex key -> { core, interval, bytesStored }
    this.totalBytesStored = 0
    this.totalBytesServed = 0
    this.running = false

    // v0.18.x — persist the set of seeded BARE-core keys so they survive a
    // relay restart. Catalog bees + any /seed-core pin are plain Hypercores
    // (not appRegistry-managed Hyperdrives), so without this they'd be
    // forgotten on restart and the relay would silently stop serving them.
    // Atomic tmp+rename (same pattern as subsidy.json / lease.json).
    this._persistPath = opts.storagePath || null
    this._persistTail = Promise.resolve()
    // While re-seeding from the persisted list on start(), suppress the
    // per-seedCore write (the file already holds exactly these keys).
    this._restoring = false
  }

  async start () {
    this.running = true
    // Re-seed cores pinned in a previous run. Their blocks already live in the
    // corestore on disk, so this re-opens + re-announces them (fast) and
    // resumes serving. Per-key failures are non-fatal.
    await this._restorePersisted()
    this.emit('started')
  }

  async seedCore (publicKeyHex) {
    if (this.cores.has(publicKeyHex)) return this.cores.get(publicKeyHex)

    const key = b4a.from(publicKeyHex, 'hex')
    const core = this.store.get({ key })
    await core.ready()

    // Download all blocks
    const range = core.download({ start: 0, end: -1 })
    range.done().catch(err => {
      // Log but don't throw — download will retry
      if (this.node?.emit) this.node.emit('download-error', { key: publicKeyHex, error: err.message })
    })

    // Periodically re-announce on the DHT
    const topic = core.discoveryKey
    this.swarm.join(topic, { server: true, client: true })

    const interval = setInterval(() => {
      if (this.running) {
        this.swarm.join(topic, { server: true, client: true })
      }
    }, this.announceInterval)

    const entry = {
      core,
      range,
      interval,
      topic,
      publicKeyHex,
      startedAt: Date.now(),
      bytesStored: 0,
      bytesServed: 0
    }

    // Track storage as blocks download
    core.on('download', (index, byteLength) => {
      entry.bytesStored += byteLength
      this.totalBytesStored += byteLength
      this.emit('block-downloaded', { publicKeyHex, index, byteLength })
    })

    core.on('upload', (index, byteLength) => {
      entry.bytesServed += byteLength
      this.totalBytesServed += byteLength
      this.emit('block-served', { publicKeyHex, index, byteLength })
    })

    this.cores.set(publicKeyHex, entry)
    // Persist the new pin so it's re-seeded after a restart (skip while we are
    // ourselves restoring from the persisted list).
    if (!this._restoring) this._persist()
    this.emit('seeding-core', { publicKeyHex, length: core.length })

    return entry
  }

  // Release a single entry's live resources WITHOUT touching the persisted
  // set. Shared by unseedCore (intentional removal) and stop() (teardown).
  async _releaseEntry (entry) {
    clearInterval(entry.interval)
    try { await this.swarm.leave(entry.topic) } catch (_) {}
    try { entry.range.destroy() } catch (_) {}
    try { await entry.core.close() } catch (_) {}
  }

  // Intentional unseed: operator no longer wants this core. Removes it from
  // the persisted set so it is NOT re-seeded on the next start.
  async unseedCore (publicKeyHex) {
    const entry = this.cores.get(publicKeyHex)
    if (!entry) return

    await this._releaseEntry(entry)

    this.totalBytesStored = Math.max(0, this.totalBytesStored - entry.bytesStored)
    this.cores.delete(publicKeyHex)
    this._persist()

    this.emit('unseeded-core', { publicKeyHex })
  }

  hasCapacity (additionalBytes = 0) {
    return (this.totalBytesStored + additionalBytes) < this.maxStorageBytes
  }

  getStats () {
    return {
      coresSeeded: this.cores.size,
      totalBytesStored: this.totalBytesStored,
      totalBytesServed: this.totalBytesServed,
      capacityUsedPct: Math.round((this.totalBytesStored / this.maxStorageBytes) * 100)
    }
  }

  async stop () {
    this.running = false
    // Teardown only — release resources but DO NOT mutate the persisted set,
    // so a restart re-seeds exactly what was pinned. (A persisting unseed here
    // would empty the list on every graceful shutdown.)
    for (const entry of this.cores.values()) {
      await this._releaseEntry(entry)
    }
    this.cores.clear()
    this.emit('stopped')
  }

  // ─── Persistence (atomic tmp+rename) ───────────────────────────────

  async _restorePersisted () {
    const keys = await this._loadPersisted()
    if (!keys.length) return
    this._restoring = true
    let restored = 0
    for (const k of keys) {
      try {
        await this.seedCore(k)
        restored++
      } catch (err) {
        this.emit('reseed-error', { publicKeyHex: k, error: err && err.message ? err.message : String(err) })
      }
    }
    this._restoring = false
    if (restored) this.emit('cores-restored', { count: restored })
  }

  _persist () {
    if (!this._persistPath) return
    this._persistTail = this._persistTail.then(() => this._writePersisted()).catch(() => {})
    return this._persistTail
  }

  async _writePersisted () {
    const tmp = this._persistPath + '.tmp'
    const data = JSON.stringify({
      schemaVersion: PERSIST_SCHEMA_VERSION,
      cores: Array.from(this.cores.keys())
    })
    try {
      await mkdir(dirname(this._persistPath), { recursive: true })
      await writeFile(tmp, data)
      await rename(tmp, this._persistPath)
    } catch (err) {
      try { await unlink(tmp) } catch (_) {}
      this.emit('persist-error', err)
    }
  }

  async _loadPersisted () {
    if (!this._persistPath) return []
    try {
      const data = JSON.parse(await readFile(this._persistPath, 'utf8'))
      if (data.schemaVersion !== PERSIST_SCHEMA_VERSION) return []
      if (!Array.isArray(data.cores)) return []
      return data.cores.filter(k => typeof k === 'string' && /^[0-9a-f]{64}$/i.test(k))
    } catch {
      // Missing/corrupt -> nothing to restore. A lost list only means the
      // operator must re-pin; no data is destroyed (blocks stay in the store).
      return []
    }
  }
}
